# masina-client

Drone-side programs for an OpenIPC camera (SSC338Q, waybeam encoder) flying over LTE.

| Program | Init script | What it does |
|---|---|---|
| `masinaclient` | `S90masinaclient` | RC link: serial (CRSF) <-> UDP to the ground station (`GROUND_IP:2223`) |
| `masinatelemetry` | `S91masinatelemetry` | telemetry to the ground station (`GROUND_IP:2224`) |
| `modem_link` | `S92modemlink` | LTE link monitor over the modem's DIAG port; one stats line per interval (0.25 s) |
| `modem_alink` | `S93modemalink` | Adaptive link: sets the encoder bitrate and frame rate from the modem stats, thermal throttling |

All of them read `/etc/masina.conf`; `enabled=true` there starts them at boot. `update_masina` (run by
`S90masinaclient`) points waybeam's `outgoing.server` at `udp://GROUND_IP:2222` on every start.

Besides the radio statistics, `modem_link` reads the serving cell over AT every 5 s and prints its channel bandwidth
(`bw`, MHz), cell identity (`cell_id`) and base station (`enb` = `cell_id` / 256: a change means another tower), NA
without an AT port. It also prints the modem's NAS messages to the core network as `event=nas` lines (attach, detach,
tracking area update, service request / reject, with the cause on rejects, e.g. `cause=10:implicitly_detached`); the
summary counts rejects and network detaches as `nas_rejects`.

---

## modem_alink

### How it works

```
modem_link --(stats lines, UDP 127.0.0.1:2225)--> modem_alink --(HTTP API)--> waybeam encoder
                                                       |
                                                       +--> ground station (GROUND_IP:2224): every change
                                                       +<-- control port 2226 (HTTP/UDP): enable, preset, ...
```

Two loops, each with one job:

```
link loop (every modem_link line, 0.25 s)          overshoot loop (every output measurement, 0.25 s)
  modem stats -> target                              target (read only) + measured output
  only it writes the target                         -> encoder bitrate (never above the target)
                                                     -> at the encoder's floor: the ladder (frame rate, ISP)
```

The **target** is what the link should carry, e.g. 4000 kbit/s. The overshoot loop never changes it; it only moves
the encoder bitrate and the ladder so that what the camera actually sends stays within it. A dark scene that makes the
encoder send 5x its bitrate lowers the encoder and the frame rate, not the target.

**1. Link loop: congestion -> target.** Congestion is a *standing* uplink queue in the modem (`qdelay_min` /
`ul_buf_min`, the smallest queue of the interval): a queue that never empties means the link carries less than is
sent. Keyframes only make short spikes that drain within the interval, so they don't count.

- *congested*: aim for a share of what the uplink carried, minus enough to empty the queue within `drain` s; while
  the target is above that, cut it (at least to `down_factor`, at most to `cut_floor` of it per line). Below it:
  hold, the queue is draining. The encoder follows a cut at once where it is above the new target.
- *clear*: after `up_after` s clear, go back to `ul_share` of what the uplink carried while congested (if that was
  within the last 10 s), then raise a small step per line up to the preset's max, **but only while the output fills
  at least `ALINK_PROBE_FILL` of the target** (default 0.8 = 80 %): a clear link says nothing about more than it is
  sent. A static scene sending 1500 leaves the target at ~1850 instead of letting it climb untested to the max.
  `ALINK_PROBE_FILL=0` raises it on a clear link whatever the output (as before the two loops). Where the encoder was
  at the target (and the ladder off) it follows the target up.
- the network's own rules (modem_link's trigger fields) refine this: *edge* (a handover/release rule within 2 dB of
  firing) = no raising; *handover* = no cuts for 1 s after the cell changes; *no service* = no raising.

Without modem stats (bench, or `modem_link` not running) the target stays where it was; at start that is the bitrate
the camera had (or the preset's max, if lower). The bitrate slider (any change from someone else) sets the target.

**2. Overshoot loop: output vs target -> encoder bitrate, then the ladder.** The output is measured every 0.25 s over
1 s (see below); after any change the loop waits 1.25 s so the window holds only frames from after it.

- **down**, the output at or above `ALINK_BITRATE_OVERSHOOT_MAX` x the target (default 1.5; while the link is
  congested anything above the target): the encoder bitrate by the overshoot, so the output should land at the target.
  At the encoder's floor (`ALINK_ENC_MIN`, 1000 kbit/s: waybeam does not encode below that; checked in the encoder
  driver, `/proc/mi_modules/mi_venc/mi_venc0`: targets of 900 ... 100 all run at MaxBitrate 1024000), one stage of
  the ladder per measurement:

  ```
  encoder -> floor  ->  frame rate to 40 (2/3)  ->  ISP stage  ->  frame rate lower (30, 20, 15, 12, 10)
                                                     despike 15     one step at a time,
                                                     sharpness 0    never below ALINK_MIN_FPS (default 15)
                                                     grayscale
  ```

  Far over (the algorithm's `jump`, e.g. 2x the target): the encoder straight to its floor and every stage expected
  to be needed, in one step. The **performance** preset already takes a stage alongside once the encoder is at or below
  2000 kbit/s (`ALINK_LADDER_FROM=<kbit/s>` overrides it for any preset, 0 = only at the floor).
- **up**, the output below 0.8 x the target for the algorithm's hold (default the preset's `up_after`, 3 s) and the
  link not struggling: the ladder back first (frame rate up to 40, the ISP settings back, frame rate up to full), then
  the encoder bitrate to where the output should fill the target, never above it. A ladder stage also comes back when
  the encoder is above its floor and sends no more than its bitrate: the ladder is only there for an encoder at its
  floor that sends more than it is told. Steps up are the algorithm's gap apart; one that has to be undone doubles the
  gap (up to 60 s), 20 s without a step down brings it back, so it does not bounce. A frame-rate step up goes to the
  highest rate the output, scaled by the frame rate, still fits at 90 % of the target (algorithms with `fit`).

With `ALINK_BITRATE_OVERSHOOT_CONTROL=false` the encoder bitrate is the target, and the ladder only runs while the
link is congested with the target at the floor (and comes back once the encoder holds the output again).

The ISP stage keeps the camera's own despike/sharpness/grayscale values first and puts them back afterwards (or the
`ALINK_ISP_*` values, if set). A dark (high-gain) or very detailed, moving scene can need far more than 1000 kbit/s
at 60 fps even at the coarsest quantizer. Measured with the earlier single-loop version, dark scene at 1440p60,
target 4000: 0 s bitrate 4000 -> 1000, 1.4 s 30 fps, 2.7 s ISP stage, 3.9 s 15 fps: output ~21 -> ~2 Mbit/s.

**Measuring the output.** From the transmit counters (`/sys/class/net/<if>/statistics/tx_bytes`, `tx_packets`) of
the interface the stream leaves on, minus IP/UDP/RTP headers per packet, averaged over 1 s. The interface is found
from waybeam's `outgoing.server` and the routing table (`wg0` in flight, `eth0` on the bench), or set with
`ALINK_IFACE`. Matches what the ground receives within ~3 %. Note: waybeam's `video0.bitrate` is in units of
1024 bit/s.

**3. Algorithms.** **`ALINK_ALGO`** (or `algo=<name|1..8>` on the control port) picks how the overshoot loop moves,
to compare in flight; the status line shows `algo=`. All react at `ALINK_BITRATE_OVERSHOOT_MAX` (1.5x the target).

| # | `ALINK_ALGO` | target from | down | back up (from 15 fps grayscale, g = grayscale) | hold | gap | encoder back up |
|---|---|---|---|---|---|---|---|
| 1 | `mid` (default) | link | one step per measurement (~1.3 s), at 2x all at once | 20g 30g 40g, color, 60 (fitting steps skipped) | `up_after` | 2 s | one step |
| 2 | `fast` | link | at the first overshoot: floor and every stage expected, at once | 60 and color at once | 1 s | 1 s | one step |
| 3 | `slow` | link | one step at least 3 s apart, never all at once | 20g 30g 40g, color, 60, one step each | 8 s | 5 s | +25 % per step |
| 4 | `coarse` | link | as mid | 40g, color, 60 | `up_after` | 2 s | one step |
| 5 | `gray_last` | link | as mid | 20g ... 60g, then color (fitting steps skipped) | `up_after` | 1.5 s | one step |
| 6 | `fixed_mid` | set bitrate | as mid | as mid | as mid | 2 s | one step |
| 7 | `fixed_fast` | set bitrate | as fast | as fast | 1 s | 1 s | one step |
| 8 | `fixed_slow` | set bitrate | as slow | as slow | 8 s | 5 s | +25 % per step |

*hold* = how long the output has to stay below 0.8x the target before the first step up. *one step* = the encoder
straight to where the output should fill the target (at most the target).

**6-8 ignore the link**: the target stays at the bitrate that was set, no congestion cuts, no probing; they run the
overshoot loop even with `ALINK_BITRATE_OVERSHOOT_CONTROL=false`. A link that congests while the output stays within
1.5x the target is not reacted to.

Simulated (the real `control()` / overshoot loop against a model scene and link, `mid`, performance): dark room at
4000 -> 1000 kbit/s, 20 fps grayscale in one step, then 40 fps grayscale (output 3500, within the 4000 target);
white wall: color, 60 fps, 4000 kbit/s ~7 s after. Link 6000 -> 2500 with a busy scene: target 4000 -> 1000 and
40 fps, then 60 fps once the target has room, then the encoder, then target and encoder together back to 4000.

**4. Thermal throttling.** Every 5 s the SoC temperature (`/sys/devices/virtual/mstar/msys/TEMP_R`) is looked up in
`/etc/temp_profile.conf` and caps the frame rate. Back up only 2 °C below the hotter band. This wins over everything
(also `ALINK_MIN_FPS`) and also works while modem_alink is disabled. It replaces the old `thermal-throttle` script,
which reads the frame rate from `/etc/majestic.yaml` and does nothing under waybeam (disable it:
`mv /etc/init.d/S96thermal /etc/init.d/off.S96thermal`).

```
# /etc/temp_profile.conf   <min>-<max> <fps|-> <scale of the full rate|-> <check every s>   first match wins
0-70       -     1       5
70-80      -     0.5     5
80-85      15    -       5
85-999     3     -       5
```
(this is also the built-in default if the file is missing)

**5. Image (ISP) settings.** Optionally modem_alink keeps three ISP settings on the camera: despike
(`nr_despike`, 0..15), sharpness (0..255) and grayscale (`color_to_gray`). waybeam loses them on every start and
reinit (it reloads the sensor bin), so every 3 s they are read back from `/api/v1/iq` and set again if needed. A key
that is not set is left alone. In a dark, high-gain scene the picture is mostly noise; measured at 1440p60 (target
1000): defaults ~30 Mbit/s, despike 15 + sharpness 0 ~15 Mbit/s, with `fpv.noiseLevel=1` (waybeam 3DNR) ~6 Mbit/s,
plus grayscale ~2 Mbit/s. They soften the picture, so set them for the conditions you fly in, or switch them over the
control port. Works while modem_alink is disabled too.

**6. Ownership.** While enabled, modem_alink owns the bitrate: a change from someone else (e.g. the ground station's
bitrate slider) is the new target, where it carries on from. The bitrate and frame rate the camera had when it took
over, or the last change from someone else, are given back when it is disabled or stops (SIGINT/SIGTERM). No stats
for 3 s: the target is held. Frame-rate changes use `/api/v1/live/set` (not written to flash).

### Presets

| Preset | Max bitrate | Cut per line (down_factor / cut_floor) | Aim when congested (ul_share, drain) | Raise after | Raise speed | Ladder from |
|---|---|---|---|---|---|---|
| `performance` | 4000 kbit/s | 0.70 / 0.25 | 70 % of uplink, 0.5 s | 3.0 s clear | ~3 %/s | 2000 kbit/s |
| `balanced` (default) | 8000 kbit/s | 0.85 / 0.50 | 80 % of uplink, 1.0 s | 2.0 s clear | ~5 %/s | the floor |
| `quality` | 16000 kbit/s | 0.90 / 0.50 | 90 % of uplink, 2.0 s | 1.0 s clear | ~8 %/s | the floor |

### /etc/masina.conf

| Key | Default | |
|---|---|---|
| `ALINK_ENABLED` | `true` | adaptive bitrate on/off (thermal works either way) |
| `ALINK_PRESET` | `balanced` | `performance`, `balanced`, `quality` |
| `ALINK_CAMERA` | `127.0.0.1:80` | waybeam HTTP API |
| `ALINK_CONTROL_PORT` | `2226` | control port (HTTP and UDP) |
| `ALINK_MIN_BITRATE` | `1` | kbit/s; the effective floor is the higher of this and `ALINK_ENC_MIN` |
| `ALINK_ENC_MIN` | `1000` | kbit/s; the encoder's own floor, the bitrate goes no lower (waybeam runs anything lower at 1000, so a lower value only adds cuts that change nothing) |
| `ALINK_LADDER_FROM` | the preset's | kbit/s at or below which the ladder starts alongside the cuts (performance 2000, others the floor; 0 = only at the floor) |
| `ALINK_MIN_FPS` | `15` | lowest frame rate the bitrate-floor logic uses |
| `ALINK_IFACE` | `auto` | interface to measure the output on; `auto` = route to waybeam's `outgoing.server` |
| `ALINK_BITRATE_OVERSHOOT_CONTROL` | `false` | the overshoot loop moves the encoder bitrate (see 2.); `false` = the encoder bitrate is the target |
| `ALINK_BITRATE_OVERSHOOT_MAX` | `1.5` | output/target at which the overshoot loop steps down (not below 1.05) |
| `ALINK_ALGO` | `mid` | overshoot loop algorithm, name or 1..8 (see 3.) |
| `ALINK_PROBE_FILL` | `0.8` | the link loop raises the target only while the output is at least this share of it; `0` = whatever the output (see 1.) |
| `ALINK_ISP_DESPIKE` | not set | ISP despike 0..15 kept on the camera (see 5.) |
| `ALINK_ISP_SHARPNESS` | not set | ISP sharpness 0..255 kept on the camera |
| `ALINK_ISP_GRAYSCALE` | not set | `true` / `false`: grayscale kept on the camera |
| `ALINK_THERMAL` | `true` | thermal throttling |
| `ALINK_TEMP_PROFILE` | `/etc/temp_profile.conf` | thermal profile |
| `GROUND_IP` | | every change is reported there on port 2224 |

### Control port (2226, HTTP or UDP)

Changes are not kept: `/etc/masina.conf` sets the values at start. Keys may be prefixed `alink.`; several at once,
separated by `&` or `;`. No query = status only. A bad key or value answers `error=bad_command`.

| Key | Values |
|---|---|
| `enable` | `0` / `1` |
| `preset` | `performance` / `balanced` / `quality` |
| `bitrate_overshoot_control` | `0` / `1` (turning it off gives back the frames it held down, the encoder bitrate goes to the target) |
| `algo` | name or `1`..`8` (see 3.) |
| `probe_fill` | `0`..`1`, e.g. `0` = raise the target on a clear link whatever the output (see 1.) |
| `bitrate_overshoot_max` | e.g. `1.8` |
| `isp_despike` | `0`..`15`, `-1` = stop managing it (the value stays until waybeam restarts) |
| `isp_sharpness` | `0`..`255`, `-1` = stop managing it |
| `isp_grayscale` | `0` / `1`, `-1` = stop managing it |

```sh
curl 'http://<drone>:2226/'                                         # status
curl 'http://<drone>:2226/?preset=performance&enable=1'
curl 'http://<drone>:2226/?bitrate_overshoot_control=1&bitrate_overshoot_max=1.8'
curl 'http://<drone>:2226/?isp_despike=15&isp_sharpness=0&isp_grayscale=1'   # dark: less noise, fewer bits
echo 'preset=quality;enable=1' | nc -u -w1 <drone> 2226
```

### Status and reports

```
ALINK;time=00:51:46;enabled=1;preset=balanced;bitrate=3000kbps;target=3000kbps;max=8000kbps;fps=60;actual=2950kbps;fps_cap=60;
      temp=44C;therm_fps=0;overshoot_control=0;overshoot_max=1.50;manual=3000kbps
```

| Field | |
|---|---|
| `bitrate` | encoder bitrate (the overshoot loop's) |
| `target` | what the link should carry (the link loop's); the encoder never goes above it |
| `max` | preset's max |
| `fps` | frame rate the camera runs |
| `actual` | measured output, kbit/s over 1 s (once the interface is known) |
| `fps_cap` | frame rate allowed by the bitrate-floor / overshoot logic |
| `isp_floor` | 1 = the ladder's ISP stage is on (despike 15, sharpness 0, grayscale) |
| `temp`, `therm_fps` | SoC temperature and the thermal frame-rate cap (0 = none) |
| `overshoot_control`, `overshoot_max`, `algo` | current overshoot loop settings |
| `probe_fill` | output/target the link loop needs before raising the target (0 = none) |
| `isp_despike`, `isp_sharpness`, `isp_grayscale` | ISP settings kept on the camera (-1 = left alone) |
| `manual` | bitrate given back on disable/exit (status reply only) |

Every change is printed and sent to `GROUND_IP:2224` with `prev=` (the encoder bitrate before, or for a target change
that the encoder did not follow, the target before) and `reason=`, plus the link fields (`qdelay`,
`queue`, `ul_rate`, `qdelay_min`, `queue_min`, `trigger`, `trigger_gap`) when it came from a stats line. Reasons:

| reason | |
|---|---|
| `start`, `enable`, `disable`, `exit` | modem_alink took over / gave the camera back |
| `congestion`, `recover`, `max` | target cut / raised / clamped to the preset's max (link loop) |
| `overshoot`, `fill` | encoder bitrate lowered / raised by the overshoot loop |
| `target` | encoder bitrate brought to the target (above it, or overshoot control off) |
| `external` | someone else changed the bitrate; it is the new target |
| `floor_fps`, `recover_fps` | frame rate lowered at the encoder floor / raised again |
| `floor_isp`, `recover_isp` | the ladder's ISP stage on / off |
| `overshoot_control_on`, `overshoot_control_off`, `overshoot_max`, `algo`, `probe_fill` | changed on the control port |
| `thermal` | thermal frame-rate cap changed |
| `isp` | ISP settings (re)applied, e.g. after waybeam restarted |
| `fps` | frame rate set back (e.g. after a cap was lifted) |
| `preset` | preset changed |
| `edge`, `handover`, `no_service`, `service` | network events from modem_link |
| `no_data` | no stats for 3 s, target held |

### waybeam API used

`GET /api/v1/get?video0.bitrate`, `?video0.fps`, `?outgoing.server`, `GET /api/v1/set?video0.bitrate=<kbit/s>`,
`GET /api/v1/live/set?video0.fps=<n>` (falls back to `/api/v1/set` on cameras without `live/set`),
`GET /api/v1/iq`, `GET /api/v1/iq/set?nr_despike=|sharpness=|color_to_gray=` (ISP settings, only when set).

### Building

The camera is armv7 hard-float. The binary is linked statically so it does not depend on the camera's glibc version
(e.g. with the Bootlin `armv7-eabihf--glibc--stable` toolchain):

```sh
TC=/path/to/armv7-eabihf--glibc--stable-2026.08-1/bin
$TC/arm-buildroot-linux-gnueabihf-gcc -march=armv7-a -mfpu=neon -mfloat-abi=hard -mtune=cortex-a7 -O2 \
    -fdata-sections -ffunction-sections -Wall -static modem_alink.c -o modem_alink -Wl,--gc-sections
$TC/arm-buildroot-linux-gnueabihf-strip modem_alink
```

(`make modem_alink` with `arm-linux-gnueabihf-gcc` works too, dynamically linked.) The `getaddrinfo` warning of a
static glibc link is harmless: only numeric addresses are resolved.

### Installing

```sh
# on the camera
/etc/init.d/S93modemalink stop
cp /usr/bin/modem_alink /usr/bin/modem_alink.orig     # once
wget -O /usr/bin/modem_alink http://<pc>:8000/modem_alink && chmod +x /usr/bin/modem_alink
/etc/init.d/S93modemalink start
```

To see its output, run it by hand instead of through the init script: `modem_alink > /tmp/alink.log 2>&1 &`.

### Testing without a modem

modem_alink reads modem_link's lines from `127.0.0.1:2225`; fake ones can be sent from the camera itself
(`socat` is on the image):

```sh
# congested: big standing queue, 0.5 Mbit/s uplink
echo "SIM;qdelay=300;ul_buf=60;ul_rate=0.50;qdelay_min=250;ul_buf_min=50" | socat - UDP-SENDTO:127.0.0.1:2225
# clear
echo "SIM;qdelay=2;ul_buf=0.5;ul_rate=8.00;qdelay_min=1;ul_buf_min=0.2" | socat - UDP-SENDTO:127.0.0.1:2225
```

Send them 4x per second (`while :; do echo ... | socat ...; sleep 0.25; done`). Expected with a detailed scene at
a 3000 target: congested -> `congestion` 3000 -> 1500 -> 1000 (target and encoder), then `floor_fps` (e.g. 40 fps)
while the output is above the target; clear -> `recover` steps of the target while the output fills it, `recover_fps`
back to 60 once it has room, then `fill` (encoder) and `recover` (both) up to the max.
