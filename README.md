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

modem_alink decides on every stats line from modem_link (every 0.25 s).

**1. Congestion -> bitrate.** Congestion is a *standing* uplink queue in the modem (`qdelay_min` / `ul_buf_min`,
the smallest queue of the interval): a queue that never empties means the link carries less than is sent.
Keyframes only make short spikes that drain within the interval, so they don't count.

- *congested*: aim for a share of what the uplink carried, minus enough to empty the queue within `drain` s; while
  the bitrate is above that, cut to it (at least to `down_factor`, at most to `cut_floor` of it per line). Below it:
  hold, the queue is draining.
- *clear*: after `up_after` s clear, go back to `ul_share` of what the uplink carried while congested (if that was
  within the last 10 s), then raise a small step per line up to the preset's max.
- the network's own rules (modem_link's trigger fields) refine this: *edge* (a handover/release rule within 2 dB of
  firing) = no raising; *handover* = no cuts for 1 s after the cell changes; *no service* = no raising.

**2. Bitrate floor -> frame rate.** The bitrate never goes below `ALINK_ENC_MIN` (1000 kbit/s: waybeam does not
encode below that). The encoder always gets the target; what it actually sends is normally not looked at. Only when
the link is **congested and the bitrate is already at the floor**, modem_alink measures the real output and, if it
is above the target, lowers the frame rate to the step expected to fit:

```
60 -> 40 -> 30 -> 20 -> 15 (-> 12 -> 10)     never below ALINK_MIN_FPS (default 15)
```

A detailed, moving scene can need far more than 1000 kbit/s at 60 fps even at the coarsest quantizer (measured at
2816x1584: full-screen noise ~11 Mbit/s at a 1000 target, ~4 Mbit/s at 15 fps).

**3. Recovery.** When the link is clear again: **frame rate first** (one step every ~3 s; going down takes ~1.3 s per step), and only once it is back
to full, the bitrate.

**Measuring the output.** From the transmit counters (`/sys/class/net/<if>/statistics/tx_bytes`, `tx_packets`) of
the interface the stream leaves on, minus IP/UDP/RTP headers per packet, averaged over 1 s. The interface is found
from waybeam's `outgoing.server` and the routing table (`wg0` in flight, `eth0` on the bench), or set with
`ALINK_IFACE`. Matches what the ground receives within ~3 %. Note: waybeam's `video0.bitrate` is in units of
1024 bit/s.

**4. Optional: bitrate overshoot control** (`ALINK_BITRATE_OVERSHOOT_CONTROL`, off by default). Watches the output
all the time, congested or not: at or above `ALINK_BITRATE_OVERSHOOT_MAX` x the target (default 1.5) it lowers the
bitrate (by the overshoot, in one step, not below the floor), and at the floor the frame rate (~1.3 s later). Without
modem stats it also recovers on its own: below 0.8 x the max for `up_after` s, frame rate first, then the bitrate in
10 % steps back to the bitrate that was set (never above it). With modem stats the link decides when to go back up,
but not while the output is still near the max.

**5. Thermal throttling.** Every 5 s the SoC temperature (`/sys/devices/virtual/mstar/msys/TEMP_R`) is looked up in
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

**6. Image (ISP) settings.** Optionally modem_alink keeps three ISP settings on the camera: despike
(`nr_despike`, 0..15), sharpness (0..255) and grayscale (`color_to_gray`). waybeam loses them on every start and
reinit (it reloads the sensor bin), so every 3 s they are read back from `/api/v1/iq` and set again if needed. A key
that is not set is left alone. In a dark, high-gain scene the picture is mostly noise; measured at 1440p60 (target
1000): defaults ~30 Mbit/s, despike 15 + sharpness 0 ~15 Mbit/s, with `fpv.noiseLevel=1` (waybeam 3DNR) ~6 Mbit/s,
plus grayscale ~2 Mbit/s. They soften the picture, so set them for the conditions you fly in, or switch them over the
control port. Works while modem_alink is disabled too.

**7. Ownership.** While enabled, modem_alink owns the bitrate: a change from someone else (e.g. the ground station's
bitrate slider) is where it carries on from. The bitrate and frame rate the camera had when it took over, or the
last change from someone else, are given back when it is disabled or stops (SIGINT/SIGTERM). No stats for 3 s: the
bitrate is held. Frame-rate changes use `/api/v1/live/set` (not written to flash).

### Presets

| Preset | Max bitrate | Cut per line (down_factor / cut_floor) | Aim when congested (ul_share, drain) | Raise after | Raise speed |
|---|---|---|---|---|---|
| `performance` | 4000 kbit/s | 0.70 / 0.25 | 70 % of uplink, 0.5 s | 3.0 s clear | ~3 %/s |
| `balanced` (default) | 8000 kbit/s | 0.85 / 0.50 | 80 % of uplink, 1.0 s | 2.0 s clear | ~5 %/s |
| `quality` | 16000 kbit/s | 0.90 / 0.50 | 90 % of uplink, 2.0 s | 1.0 s clear | ~8 %/s |

### /etc/masina.conf

| Key | Default | |
|---|---|---|
| `ALINK_ENABLED` | `true` | adaptive bitrate on/off (thermal works either way) |
| `ALINK_PRESET` | `balanced` | `performance`, `balanced`, `quality` |
| `ALINK_CAMERA` | `127.0.0.1:80` | waybeam HTTP API |
| `ALINK_CONTROL_PORT` | `2226` | control port (HTTP and UDP) |
| `ALINK_MIN_BITRATE` | `1` | kbit/s; the effective floor is the higher of this and `ALINK_ENC_MIN` |
| `ALINK_ENC_MIN` | `1000` | kbit/s; the encoder's own floor, the bitrate goes no lower |
| `ALINK_MIN_FPS` | `15` | lowest frame rate the bitrate-floor logic uses |
| `ALINK_IFACE` | `auto` | interface to measure the output on; `auto` = route to waybeam's `outgoing.server` |
| `ALINK_BITRATE_OVERSHOOT_CONTROL` | `false` | watch the output all the time (see 4.) |
| `ALINK_BITRATE_OVERSHOOT_MAX` | `1.5` | output/target that triggers it (not below 1.05) |
| `ALINK_ISP_DESPIKE` | not set | ISP despike 0..15 kept on the camera (see 6.) |
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
| `bitrate_overshoot_control` | `0` / `1` (turning it off gives back the frames and bitrate it held down) |
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
ALINK;time=00:51:46;enabled=1;preset=balanced;bitrate=3000kbps;max=8000kbps;fps=60;actual=2950kbps;fps_cap=60;
      temp=44C;therm_fps=0;overshoot_control=0;overshoot_max=1.50;manual=3000kbps
```

| Field | |
|---|---|
| `bitrate` | target given to the encoder |
| `max` | preset's max |
| `fps` | frame rate the camera runs |
| `actual` | measured output, kbit/s over 1 s (once the interface is known) |
| `fps_cap` | frame rate allowed by the bitrate-floor / overshoot logic |
| `temp`, `therm_fps` | SoC temperature and the thermal frame-rate cap (0 = none) |
| `overshoot_control`, `overshoot_max` | current overshoot-control settings |
| `isp_despike`, `isp_sharpness`, `isp_grayscale` | ISP settings kept on the camera (-1 = left alone) |
| `manual` | bitrate given back on disable/exit (status reply only) |

Every change is printed and sent to `GROUND_IP:2224` with `prev=` and `reason=`, plus the link fields (`qdelay`,
`queue`, `ul_rate`, `qdelay_min`, `queue_min`, `trigger`, `trigger_gap`) when it came from a stats line. Reasons:

| reason | |
|---|---|
| `start`, `enable`, `disable`, `exit` | modem_alink took over / gave the camera back |
| `congestion`, `recover`, `max` | bitrate cut / raised / clamped to the preset's max |
| `external` | someone else changed the bitrate; carried on from there |
| `floor_fps`, `recover_fps` | frame rate lowered at the bitrate floor / raised again |
| `overshoot` | bitrate cut by overshoot control |
| `overshoot_control_on`, `overshoot_control_off`, `overshoot_max` | changed on the control port |
| `thermal` | thermal frame-rate cap changed |
| `isp` | ISP settings (re)applied, e.g. after waybeam restarted |
| `fps` | frame rate set back (e.g. after a cap was lifted) |
| `preset` | preset changed |
| `edge`, `handover`, `no_service`, `service` | network events from modem_link |
| `no_data` | no stats for 3 s, bitrate held |

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
a 3000 target: congested -> `congestion` 3000 -> 1500 -> 1000, then `floor_fps` (e.g. 15 fps); clear ->
`recover_fps` 20 -> 30 -> 40 -> 60, then `recover` steps of the bitrate.
