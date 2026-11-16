# masina-client

Drone-side programs for an OpenIPC camera (SSC338Q, waybeam encoder) flying over LTE.

| Program | Init script | What it does |
|---|---|---|
| `masinaclient` | `S90masinaclient` | RC link: serial (CRSF) <-> UDP to the ground station (`GROUND_IP:2223`) |
| `masinatelemetry` | `S91masinatelemetry` | telemetry to the ground station (`GROUND_IP:2224`) |
| `modem_link` | `S92modemlink` | LTE link monitor over the modem's DIAG port; one stats line per interval (0.25 s) |
| `modem_alink` | `S93modemalink` | Adaptive link: sets the encoder bitrate, frame rate and noise filtering from the modem stats; thermal throttling |

All of them read `/etc/masina.conf`; `enabled=true` there starts them at boot. `update_masina` (run by
`S90masinaclient`) points waybeam's `outgoing.server` at `udp://GROUND_IP:2222` on every start.

### masinaclient: INAV's altitude above sea level

INAV's CRSF telemetry only sends the altitude over its zero point (about where it armed). For the altitude above
sea level, masinaclient asks the FC every `MSP_POLL_MS` (default `1000`, `0` = never) for waypoint #255, its
current position: MSP_WP (118) as an MSPv1 request inside a CRSF frame (type `0x7A`, 10 bytes:
`C8 08 7A C8 EA 30 01 76 FF EA`), written right after an RC frame so the two never interleave. INAV answers on its
CRSF telemetry with a `0x7B` frame (latitude, longitude and the altitude above sea level in cm), which goes to the
ground with everything else the FC sends; moonlight shows it as `⛰️` under `⬆`. INAV only answers while its CRSF
telemetry runs (as it does when the ground station gets its GPS and attitude), each answer takes one telemetry slot,
hence once a second.

---

## modem_alink: how the link behaves

```
modem_link --(stats line every 0.25 s, UDP 127.0.0.1:2225)--> modem_alink --(HTTP API)--> waybeam
                                                                   |
                                                                   +--> ground station (GROUND_IP:2224): every change
                                                                   +<-- control port 2226 (HTTP/UDP)
```

modem_alink judges the link **only from the modem's own statistics**. It never looks at what the camera actually
sends (no output measurement, no overshoot control): the modem's uplink queue says whether the link keeps up.

### What it reads

On every stats line from modem_link (every 0.25 s; if several are waiting, only the newest counts):

| Field | Used as |
|---|---|
| `qdelay_min`, `ul_buf_min` | the **standing queue**: the smallest delay (ms) and queue (KB) of the interval. A queue that never empties within the interval means the link carries less than is sent. A keyframe only makes a short spike that drains within the interval, so it doesn't count. Without `ul_buf_min` (modems that only log `bsr`) the queue is worked out from `qdelay_min` x `ul_rate`. |
| `qdelay`, `ul_buf` / `bsr` | the interval averages, only for an older modem_link without `qdelay_min` |
| `ul_rate` | what the uplink carried (Mbit/s); while a queue is waiting, the modem sends all the link gives it, so this is the link's capacity |
| `trigger`, `trigger_gap` | the network's measurement rule closest to firing and how many dB it has left (handover / band search / release coming) |
| `earfcn`, `pci` | the serving cell (a change = handover; missing = no service) |

### Every line: classify the link

| State | Standing queue (`qdelay_min` / `ul_buf_min`) | Then |
|---|---|---|
| **congested** | delay >= `qmin_high` **and** queue >= `qbytes_min`, **or** queue >= `qbytes_high` | cut the bitrate; at the floor, the ladder |
| **clear** | delay < `qmin_clear` **or** queue < `qbytes_clear` | after `up_after` s clear: ladder back, then raise the bitrate |
| neither | in between | hold everything; the clear timer starts again |

(The numbers per preset are in the table below. With an older modem_link the averages are used the same way, with
`qdelay_high` / `qdelay_clear`.)

### Congested: cut the bitrate

- **Aim** = `ul_share` x `ul_rate` - standing queue x 8 / `drain` (kbit/s): a share of what the link carries, minus
  enough to empty the queue within `drain` seconds.
- If the bitrate is above the aim, it is **cut to the aim**, but per line at least to `down_factor` of the bitrate and
  at most to `cut_floor` of it (one stalled interval reads as ~0 uplink, so no single line can cut further than that).
  Below the aim it holds: the queue is draining.
- At most one change per 0.2 s (one per stats line).
- Without `ul_rate`: cut by `down_factor` on the first congested line, and again only while the queue keeps growing.
- Never below `ALINK_MIN_BITRATE` (the floor, default 1000 kbit/s: stock waybeam doesn't encode below that) and never
  above the preset's max.

### Congested at the floor: the ladder

When the bitrate is at the floor and the link is still congested (and `ALINK_LINK_LADDER` is on), the picture is made
cheaper, one stage at a time:

```
bitrate at floor -> 40 fps (2/3)    -> grayscale -> 30 fps (1/2) -> 20 fps -> 15 fps -> 12 fps -> 10 fps
                    despike 15                                      (never below ALINK_MIN_FPS, default 15)
                    sharpness 0
```

- **Pace:** a stage at most every `ladder_gap` s (performance 0.5 s, balanced and quality 1.25 s), counted both from
  the last stage and from the last bitrate change. 0.5 s is two stats lines: the first line fully after a change.
- **Hold while draining:** no stage while the standing queue is on course to be empty within 2 s, at the rate it has
  fallen since the last change (congestion start, bitrate cut or stage). So when a stage works, the ladder stops
  there and doesn't keep going down while the queue from before drains.
- No stage within 1 s of a handover (see below).
- The frame rates are fractions of the camera's own rate (60 -> 40, 30, 20, 15, 12, 10), set with
  `/api/v1/live/set` (not written to flash).
- The ISP values: despike (`nr_despike`) 15 and sharpness 0 at the first stage, grayscale (`color_to_gray`) at the
  second. The camera's own values are read first and put back on the way up (a setting the camera had on auto comes
  back as a fixed value until waybeam restarts). While forced, they are checked every 3 s and set again, since waybeam
  loses them on every restart.

**Note:** the ladder only helps where fewer frames or less noise make the camera send less, i.e. when the scene
needs more than the target (dark, noisy, detailed). A camera that already meets its 1000 kbit/s target puts the same
bits into fewer frames, so on a link that can't carry even the floor, the ladder walks to the bottom without the
queue shrinking. With a waybeam that encodes lower, a lower `ALINK_MIN_BITRATE` lets the bitrate go down instead.

`ALINK_LINK_LADDER=false` (or `link_ladder=0` on the control port): the bitrate stops at the floor and nothing else
changes.

While the camera is thermally throttled (see below), frame-rate stages that wouldn't go below the thermal cap change
nothing, so they are skipped: capped at 15 fps, the stages are despike/sharpness, grayscale, then 12 and 10 fps.

### Clear: back up

After the link has been clear for `up_after` s without a break:

1. **The ladder first**, one stage per 3 s: 30 fps (from anything lower, in one step), grayscale off, 40 fps, then
   the full frame rate with despike and sharpness back (frame-rate stages above a thermal cap are skipped). If a stage
   down comes within the current wait + `ladder_gap`
   + 1 s of a stage up (it didn't hold), the wait between stages up doubles, up to 60 s; 20 s without a stage down
   brings it back to 3 s.
2. **Then the bitrate**, one step per line (0.25 s):
   - within 10 s of the last congestion: straight back to `ul_share` x the uplink rate seen while congested (the queue
     has drained, the link carried that), then a quarter step at a time from there (that is where it congested);
   - otherwise a step of `up_step` x the bitrate, at least 1 % of the preset's max (it probes for more);
   - at least 25 kbit/s per step, up to the preset's max.

### The network's own warnings

From modem_link's `trigger` fields and the serving cell; each is reported once when it starts:

| reason | When | Effect |
|---|---|---|
| `edge` | a rule other than A1 within 2 dB of firing (left again at 3 dB): band search, handover or release coming | nothing goes up (bitrate or ladder); cuts and stages down still happen: at the cell edge the uplink is short of transmit power |
| `handover` / `service` | the serving cell changed, or came back after a loss | for 1 s no cuts, no stages down and nothing goes up: the queue the switch built drains on the new cell, usually the better one |
| `no_service` | no serving cell (the queue fields are NA then) | nothing goes up |

### Thermal throttling

Every 5 s the SoC temperature (`/sys/devices/virtual/mstar/msys/TEMP_R`) is looked up in `/etc/temp_profile.conf`;
the first line it falls in caps the frame rate (`thermal`, `therm_fps=` in the status; moonlight shows OVERHEATING
while it is set):

```
# /etc/temp_profile.conf   <min>-<max> <fps|-> <scale of the full rate|-> <check every s>   first match wins
0-70       -     1       5
70-80      -     0.5     5
80-85      15    -       5
85-999     3     -       5
```

(this is also the built-in default if the file is missing: full rate below 70 °C, half from 70, 15 fps from 80, 3 fps
from 85). The repo's `temp_profile.conf` has exactly these lines to start from; edit it and copy it to
`/etc/temp_profile.conf` on the camera (it is read again on every check, so a change applies without a restart). A cooler band only takes over 2 °C below the hotter one (from 80-85 back to 70-80 at 78 °C), so a
temperature on the edge doesn't flap. The cap wins over everything, the ladder and `ALINK_MIN_FPS` too, and it also
works while the adaptive link is disabled. On `enable=0` the frame rate goes back no higher than the cap; on exit it
goes back to full. It replaces the old `thermal-throttle` script, which reads the frame rate from `/etc/majestic.yaml`
and does nothing under waybeam (disable it: `mv /etc/init.d/S96thermal /etc/init.d/off.S96thermal`).

### Presets

| | performance (default) | balanced | quality |
|---|---|---|---|
| max bitrate | 4000 kbit/s | 8000 kbit/s | 16000 kbit/s |
| congested: `qmin_high` / `qbytes_min` / `qbytes_high` | 10 ms / 5 KB / 50 KB | 20 ms / 10 KB / 100 KB | 40 ms / 20 KB / off |
| clear: `qmin_clear` / `qbytes_clear` | 3 ms / 5 KB | 5 ms / 5 KB | 10 ms / 10 KB |
| aim: `ul_share` / `drain` | 70 % / 0.5 s | 80 % / 1.0 s | 90 % / 2.0 s |
| cut per line: `down_factor` / `cut_floor` | 0.70 / 0.25 | 0.85 / 0.50 | 0.90 / 0.50 |
| raise after (`up_after`) | 3.0 s clear | 2.0 s clear | 1.0 s clear |
| raise per line (`up_step`) | 0.75 % (~3 %/s) | 1.25 % (~5 %/s) | 2 % (~8 %/s) |
| ladder stage every (`ladder_gap`) | 0.5 s | 1.25 s | 1.25 s |
| older modem_link: `qdelay_high` / `qdelay_clear` | 50 / 20 ms | 50 / 25 ms | 100 / 40 ms |

Max to the floor takes one line in performance (4000 x 0.25 = 1000), up to 3 lines (0.5 s) in balanced and 4 lines
(0.75 s) in quality when the link drops hard; when it only weakens, the cuts follow the aim.

### Examples (performance, simulated)

The link drops to 0.6 Mbit/s for 15 s (it can't carry even the floor), normal scene:

```
 0.00  congestion   4000 -> 1000 kbit/s          (one line)
 0.50  floor_isp + floor_fps   40 fps, despike/sharpness
 1.00  floor_isp    grayscale
 1.50  floor_fps    30 fps
 2.00  floor_fps    20 fps
 2.50  floor_fps    15 fps                       (ALINK_MIN_FPS)
15.00  the link is back; the queue drains, clear
19.00  recover_fps  30 fps                       (3 s clear)
22.00  recover_isp  grayscale off
25.00  recover_fps  40 fps
28.00  recover_isp + recover_fps   60 fps, despike/sharpness back
28.25  recover      1040 ... 4000 kbit/s at 46.75 (40 kbit/s per line: the congestion was over 10 s ago)
```

A dark scene that needs 3 Mbit/s at 60 fps, the link drops to 2 Mbit/s for 15 s:

```
 0.00  congestion   4000 -> 1000
 0.50  40 fps + despike/sharpness: the camera now sends less than the link carries, the queue drains: holds there
 4.75  clear 3 s -> back to 60 fps: too much again -> 5.25 40 fps (the wait before the next try doubles: 6 s)
11.25  60 fps -> 11.75 40 fps (12 s)
23.75  60 fps (the link has been back since 15 s), then the bitrate up to 4000 by 42.50
```

### The camera

- **Start:** modem_alink reads the camera's bitrate and frame rate (polled until it answers) and clamps the bitrate to
  the preset's max (`max`).
- **Owning the bitrate:** the camera is re-read every 3 s. A bitrate more than 2 % off what modem_alink set came from
  someone else (e.g. the ground station's bitrate slider): it carries on from there (`external`), and that is what it
  gives back later. A frame rate it lowered that the camera lost (encoder restart) is set again.
- **Giving back:** on `enable=0` or exit (SIGINT/SIGTERM), the bitrate it took over (or the last external one), the
  full frame rate and the camera's ISP values go back.
- **No stats:** 3 s without a stats line -> `no_data`, nothing changes until they come back.
- waybeam API used: `GET /api/v1/get?video0.bitrate`, `?video0.fps`, `GET /api/v1/set?video0.bitrate=<kbit/s>`,
  `GET /api/v1/live/set?video0.fps=<n>` (falls back to `/api/v1/set` on cameras without `live/set`), `GET /api/v1/iq`,
  `GET /api/v1/iq/set?nr_despike=|sharpness=|color_to_gray=`.

### /etc/masina.conf

| Key | Default | |
|---|---|---|
| `ALINK_ENABLED` | `true` | adaptive link on/off |
| `ALINK_PRESET` | `performance` | `performance`, `balanced`, `quality` |
| `ALINK_MIN_BITRATE` | `1000` | kbit/s, the floor: the bitrate goes no lower, the ladder starts there |
| `ALINK_MIN_FPS` | `15` | the ladder's lowest frame rate |
| `ALINK_LINK_LADDER` | `true` | the ladder past the floor (see above) |
| `ALINK_THERMAL` | `true` | thermal throttling |
| `ALINK_TEMP_PROFILE` | `/etc/temp_profile.conf` | thermal profile |
| `ALINK_CAMERA` | `127.0.0.1:80` | waybeam HTTP API |
| `ALINK_CONTROL_PORT` | `2226` | control port (HTTP and UDP) |
| `GROUND_IP` | | every change is reported there on port 2224 |

### Control port (2226, HTTP or UDP)

Changes are not kept: `/etc/masina.conf` sets the values at start. Keys may be prefixed `alink.`; several at once,
separated by `&` or `;`. No query = status only. A bad key or value answers `error=bad_command` (HTTP 400).

| Key | Values |
|---|---|
| `enable` | `0` / `1` |
| `preset` | `performance` / `balanced` / `quality` |
| `link_ladder` | `0` / `1` |

```sh
curl 'http://<drone>:2226/'                                    # status
curl 'http://<drone>:2226/?preset=balanced&link_ladder=0'
echo 'preset=quality;enable=1' | nc -u -w1 <drone> 2226
```

### Status and reports

```
ALINK;time=00:51:46;enabled=1;preset=performance;bitrate=1000kbps;max=4000kbps;fps=30;fps_cap=30;isp_floor=2;
      link_ladder=1;temp=64C;therm_fps=0;manual=3000kbps
```

| Field | |
|---|---|
| `bitrate` | target given to the encoder (waybeam counts in units of 1024 bit/s) |
| `max` | the preset's max |
| `fps` | frame rate the camera runs |
| `fps_cap` | frame rate the ladder allows |
| `isp_floor` | the ladder's ISP stage: 0 off, 1 despike 15 + sharpness 0, 2 grayscale too |
| `link_ladder` | 1 = the ladder past the floor is on |
| `temp`, `therm_fps` | SoC temperature and the thermal frame-rate cap (0 = none); missing until the temperature was read |
| `manual` | bitrate given back on disable/exit (status reply only) |

Every change is printed and sent to `GROUND_IP:2224` with `prev=` and `reason=`, plus the link fields (`qdelay`,
`queue`, `ul_rate`, `qdelay_min`, `queue_min`, `trigger`, `trigger_gap`) when it came from a stats line:

| reason | |
|---|---|
| `start`, `enable`, `disable`, `exit` | modem_alink took over / gave the camera back |
| `max` | bitrate clamped to the preset's max |
| `congestion`, `recover` | bitrate cut / raised |
| `floor_fps`, `floor_isp` | a ladder stage down |
| `recover_fps`, `recover_isp` | a ladder stage back up |
| `external` | someone else changed the bitrate; carried on from there |
| `fps` | frame rate set again (e.g. after the camera lost it) |
| `thermal` | the thermal frame-rate cap changed |
| `preset`, `link_ladder_on`, `link_ladder_off` | changed on the control port |
| `edge`, `handover`, `service`, `no_service` | network events from modem_link |
| `no_data` | no stats for 3 s, everything held |

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
wget -O /etc/temp_profile.conf http://<pc>:8000/temp_profile.conf      # optional: the thermal profile
/etc/init.d/S93modemalink start
```

To see its output, run it by hand instead of through the init script: `modem_alink > /tmp/alink.log 2>&1 &`
(stop it with `killall modem_alink`; the init script only stops the copy it started).

### Testing without a modem

modem_alink reads modem_link's lines from `127.0.0.1:2225`; fake ones can be sent from the camera itself
(`socat` is on the image):

```sh
# congested: big standing queue, 0.5 Mbit/s uplink
echo "SIM;qdelay=300;ul_buf=60;ul_rate=0.50;qdelay_min=250;ul_buf_min=50" | socat - UDP-SENDTO:127.0.0.1:2225
# clear
echo "SIM;qdelay=2;ul_buf=0.5;ul_rate=8.00;qdelay_min=1;ul_buf_min=0.2" | socat - UDP-SENDTO:127.0.0.1:2225
```

Send them 4x per second (`while :; do echo ... | socat ...; sleep 0.25; done`). Expected with performance from a
3000 kbit/s bitrate, 10 s congested then clear (simulated):

```
 0.00  congestion   3000 -> 1000
 0.50  floor_isp, floor_fps 40     1.00  floor_isp (grayscale)     1.50  floor_fps 30
 2.00  floor_fps 20                2.50  floor_fps 15
10.00  clear lines start
13.00  recover_fps 30     16.00  recover_isp     19.00  recover_fps 40     22.00  recover_isp + recover_fps 60
22.25  recover 1040 ... 4000 by ~41 s
```

The fake queue never shrinks, so the ladder runs all the way down; a real link that recovers stops it earlier.
