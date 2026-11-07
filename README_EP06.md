# Quectel EP06-E

LTE Cat 6 module with carrier aggregation and uplink 64QAM. Its Qualcomm chipset is newer than the SIM7600's and logs newer versions of most DIAG packets; `modem_link` decodes them on the **`modem/ep06` branch** (this readme describes that branch). It covers what the modem can do, how it is set up, real output from it, and the full reference of `modem_link`'s fields and events, with the EP06's extra fields.

- [Capabilities](#capabilities)
- [Setup](#setup)
- [Example output](#example-output)
- [Measured on this setup](#measured-on-this-setup)
- [How the EP06 differs](#how-the-ep06-differs)
- [Known issues](#known-issues)
- [Running it](#running-it)
- [Line format](#line-format)
- [Interval fields](#interval-fields)
- [Events](#events)
- [Summary line](#summary-line)
- [Reading the link](#reading-the-link)
- [modem_alink](#modem_alink)
- [Where the values come from](#where-the-values-come-from)
- [Other modems](#other-modems)

---

## Capabilities

| | |
|---|---|
| Module | Quectel EP06-E (mini PCIe), firmware EP06ELAR04A20M4G |
| Chipset | Qualcomm, a newer generation than the MDM9607: it logs newer versions of most DIAG packets |
| LTE category | Cat 6 down (two carriers), uplink 64QAM. Measured: 74.5 Mbit/s down sustained (peak second 93 Mbit/s), 16 Mbit/s up without power limiting at −88 dBm |
| Bands | LTE 1, 3, 5, 7, 8, 20, 28, 32, 38, 40, 41; UMTS 1, 3, 5, 8. Seen here: band 3 (1800 MHz), 8 (900 MHz), 20 (800 MHz) |
| Carrier aggregation | Yes: two downlink carriers. The network keeps swapping which band is the main carrier (band 20, 3 and 8 in changing pairs) |
| MIMO | 2×2 on each carrier |
| Uplink | QPSK, 16QAM, 64QAM; only on the main carrier |
| USB | `2c7c:0306`. `AT+QCFG="usbnet"`: 0 QMI (factory default), 1 ECM, 2 MBIM. **No RNDIS.** Runs in ECM here (setup below) |
| Serial ports | `ttyUSB0` DIAG, `ttyUSB1` GPS (NMEA), `ttyUSB2` AT, `ttyUSB3` AT |
| Useful AT commands | `AT+QCAINFO` (both carriers: band, RSRP, RSRQ, RSSI, SINR), `AT+QRSRP` (RSRP per antenna), `AT+QENG="servingcell"`, `AT+QTEMP` (three sensors), `AT+QCFG="usbnet"`, `AT+QCFG="qcautoconnect"`, `AT$QCRMCALL` (start a data call), `AT+QCFG="dl_256qam"` |
| What `modem_link` decodes | Everything, on the `modem/ep06` branch; the SIM7600 code it branched from (`7b07d92`) shows mostly NA or wrong values on an EP06. Two extra field groups: the second carrier (`scc_*`) and `dl_scc_rate`. |

---

## Setup

**ECM mode with its own dialing**, set once (stored in the modem):

```
AT+QCFG="usbnet",1          ECM: Ethernet over USB (cdc_ether)
AT+QCFG="qcautoconnect",1   dial by itself after every boot (this firmware has no AT+QNETDEVCTL)
AT+CFUN=1,1                 reset
```

The modem then hands out 192.168.225.x by DHCP and routes, like the SIM7600 in RNDIS mode. If it ever comes up
without a connection, `AT$QCRMCALL=1,1` starts the data call by hand.

**On this PC**, `/etc/udev/rules.d/78-ep06.rules`:

```
ACTION=="add|change", SUBSYSTEMS=="usb", ATTRS{idVendor}=="2c7c", ATTRS{idProduct}=="0306", ENV{ID_MM_DEVICE_IGNORE}="1"
ACTION=="add", SUBSYSTEM=="net", SUBSYSTEMS=="usb", ATTRS{idVendor}=="2c7c", ATTRS{idProduct}=="0306", NAME="usb0", ENV{NM_UNMANAGED}="1"
```

ModemManager leaves it alone, NetworkManager too, the interface is `usb0`, and the existing
`iface usb0 inet dhcp` / `sim7600.service` bring it up. Without the first line ModemManager holds the DIAG port
itself and `modem_link` can't open it.

Only plug in one of SIM7600 / EP06 at a time when both have their rules: both claim `usb0`.

**On the drone** the same as the SIM7600: `S92modemlink` starts `modem_link 0.25`, `S93modemalink` starts
`modem_alink`. Build from the `modem/ep06` branch.

---

## Example output

Real lines recorded live on 24 Oct 2026. The interval lines and the summary come from the final `modem/ep06`
code; the handover events from an earlier build of the same branch (event lines haven't changed since).

**Idle, both carriers configured:**

```
EP06;time=21:32:31;dl_tbs=9;dl_bler=0.0%;dl_harq_retx=0;dl_harq_retx_pct=0.0%;dl_resid=0;dl_mcs=9.6;dl_rbs=2.9;dl_mimo=12%;dl_rate=0.00Mbps;dl_scc_rate=0.00Mbps;pdcch_agg=1.12;ul_tx=58;ul_harq_retx=0;ul_harq_retx_pct=0.0%;ul_nack=0;ul_nack_pct=0.0%;ul_rate=0.00Mbps;ul_grant=0.05Mbps;ul_grant_used=7%;ul_rbs=2.0;ul_mod=16QAM;ul_coderate=0.78;ul_pwr=5.1dBm;ul_txpwr=9.6dBm;ul_pwrlim=0.0%;ul_pc_corr=2.5dB;pathloss=107.0dB;ul_buf=0.0KB;ul_buf_max=0.1KB;ul_buf_min=0.0KB;bsr=0.0KB;qdelay=0ms;qdelay_max=1ms;qdelay_min=0ms;qwarn=0;phr=12dB;rlc_ul_retx=0;rlc_ul_nack=0;rlc_ul_tpoll=0;rlc_dl_retx=0;rlc_dl_nack=0;rlc_dl_drop=0;rlc_dl_treord=0;pdcp_ul_discard=0;cqi0=12.0;cqi1=14.0;ri=2.0;temp=39C;vbat=3.61V;earfcn=6400;pci=186;rsrp0=-92.2dBm;rsrp1=-90.2dBm;rsrp_diff=-2.0dB;snr0=15.7dB;snr1=15.7dB;rsrq=-8.1dB;rssi=-64.9dBm;ncells=1;nb_earfcn=6400;nb_pci=187;nb_rsrp=-102.3dBm;nb_rsrq=-18.6dB;ho_margin=10.1dB;scc_earfcn=1850;scc_pci=186;scc_rsrp=-107.7dBm;scc_rsrq=-13.1dB;scc_sinr=8dB;trigger=NA;trigger_gap=NA;trigger_nb=NA;trigger_held=NA;trigger_ttt=NA;rlm_oos=0%;t310=0
```

- Main carrier band 20 (`earfcn=6400`), cell 186, RSRP −92/−90 dBm (both antennas balanced), SNR 16 dB, rank 2.
- Second carrier band 3 (`scc_earfcn=1850`) at −107.7 dBm, SINR 8 dB (from `AT+QCAINFO`).
- The neighbour is a real handover candidate (cell 187 on band 20), not the second carrier.

**20 Mbit/s offered download, both carriers carrying:**

```
EP06;time=21:32:36;dl_tbs=619;dl_bler=6.8%;dl_harq_retx=47;dl_harq_retx_pct=7.6%;dl_resid=4;dl_mcs=21.7;dl_rbs=48.8;dl_mimo=58%;dl_rate=11.95Mbps;dl_scc_rate=4.07Mbps;pdcch_agg=1.37;ul_tx=243;ul_harq_retx=1;ul_harq_retx_pct=0.4%;ul_nack=0;ul_nack_pct=0.0%;ul_rate=0.17Mbps;ul_grant=0.32Mbps;ul_grant_used=56%;ul_rbs=2.8;ul_mod=16QAM;ul_coderate=0.75;ul_pwr=-4.0dBm;ul_txpwr=10.3dBm;ul_pwrlim=0.0%;ul_pc_corr=2.4dB;pathloss=107.0dB;ul_buf=0.1KB;ul_buf_max=1.2KB;ul_buf_min=0.0KB;bsr=0.1KB;qdelay=2ms;qdelay_max=19ms;qdelay_min=0ms;qwarn=0;phr=12dB;rlc_ul_retx=NA;rlc_ul_nack=NA;rlc_ul_tpoll=NA;rlc_dl_retx=0;rlc_dl_nack=0;rlc_dl_drop=0;rlc_dl_treord=0;pdcp_ul_discard=0;cqi0=11.8;cqi1=14.0;ri=2.0;temp=41C;vbat=3.61V;earfcn=6400;pci=186;rsrp0=-92.3dBm;rsrp1=-90.2dBm;rsrp_diff=-2.1dB;snr0=14.8dB;snr1=15.2dB;rsrq=-8.0dB;rssi=-65.1dBm;ncells=1;nb_earfcn=6400;nb_pci=187;nb_rsrp=-102.4dBm;nb_rsrq=-17.6dB;ho_margin=6.0dB;scc_earfcn=1850;scc_pci=186;scc_rsrp=-105.3dBm;scc_rsrq=-10.1dB;scc_sinr=10dB;trigger=NA;trigger_gap=NA;trigger_nb=NA;trigger_held=NA;trigger_ttt=NA;rlm_oos=0%;t310=0
```

- 11.95 Mbit/s delivered (the test was rate-limited), 4.07 of it over the band 3 carrier (`dl_scc_rate`).
- MIMO on 58 % of subframes, MCS 21.7, 6.8 % first-transmission BLER.
- `rlc_ul_*` = NA: the EP06 only logs RLC uplink statistics now and then.

**Handover band 20 → band 8, with rules for the second carrier:**

```
EP06;time=20:56:13.609;event=meas_config;rules=5:A5[serving<rsrp-44dBm&nb>rsrp-112dBm,hys0dB,ttt640ms]@3500;gaps=gp0:24;known=partial
EP06;time=20:56:14.472;event=meas_report;rule=5:A5@3500;srv_rsrp=-93dBm;srv_rsrq=-8dB;cells=186:-85dBm:-12.5dB
EP06;time=20:56:14.523;event=handover;from_pci=186;from_earfcn=6400;to_pci=186;to_earfcn=3500
EP06;time=20:56:14.523;event=meas_config;rules=none;gaps=gp0:24;known=partial
EP06;time=20:56:14.530;event=handover_done;pci=186;earfcn=3500;duration=21ms
EP06;time=20:56:14.572;event=rach;reason=handover;result=success;contention=free;ta=15;distance=1172m
EP06;time=20:56:14.573;event=meas_config;rules=1:A3[nb>serving+3dB,hys1dB,ttt320ms]@3500,2:A2[serving<rsrp-114dBm,hys2dB,ttt320ms]@3500,3:A2[serving<rsrp-123dBm,hys1dB,ttt40ms]@1850,4:A1[serving>rsrp-123dBm,hys1dB,ttt40ms]@1850;gaps=gp0:24;known=partial
EP06;time=20:56:14.630;event=meas_report;rule=4:A1@1850;srv_rsrp=-85dBm;srv_rsrq=-12.5dB;cells=none
EP06;time=20:56:14.670;event=meas_config;rules=1:A3[nb>serving+3dB,hys1dB,ttt320ms]@3500,2:A2[serving<rsrp-114dBm,hys2dB,ttt320ms]@3500,3:A2[serving<rsrp-123dBm,hys1dB,ttt40ms]@1850;gaps=gp0:24;known=partial
```

The network's A5 rule for band 8 (any cell above −112 dBm), the modem's report at −85 dBm, the handover after
51 ms, completion in 21 ms, random access (1172 m). The new rules include an A2 and an A1 **on 1850**: those are
about the second carrier (band 3), not the main one.

**Summary (13 s):**

```
EP06;event=summary;duration=13s;dl_total=8.1MB;dl_avg=5.04Mbps;dl_peak=11.95Mbps;dl_bler=7.3%;dl_harq_retx=252;dl_harq_retx_pct=7.3%;dl_resid=18;ul_total=0.2MB;ul_avg=0.09Mbps;ul_peak=0.20Mbps;ul_harq_retx=10;ul_harq_retx_pct=0.6%;ul_nack=1;ul_nack_pct=0.1%;ul_pwrlim=0.0%;ul_grant_used=51.6%;pathloss_min=107dB;pathloss_max=107dB;ul_buf_max=15.1KB;qdelay_max=242ms;qwarn_intervals=0;intervals=13;rlc_ul_retx=0;rlc_ul_nack=0;rlc_dl_retx=0;rlc_dl_nack=0;rlc_dl_drop=0;pdcp_ul_discard=0;t310_intervals=0;rrc_setups=0;rrc_releases=0;meas_reports=0;handovers=0;handovers_done=0;reestablishments=0;temp_min=39C;temp_max=41C;vbat_min=3.61V;vbat_max=3.61V
```

---

## Measured on this setup

| Situation | Values |
|---|---|
| Band 20 main carrier, −88 to −92 dBm | Both antennas balanced. Uplink 16 Mbit/s at 64QAM on ~33 resource blocks, 16 dBm, no power limiting, standing queue 2–6 ms. Downlink MIMO on 58–73 % of subframes. |
| Two carriers, unthrottled download | 74.5 Mbit/s sustained (peak second 93 Mbit/s): ~39 on the main carrier (band 3, 100 resource blocks, single stream) + ~33 on band 8 (2×2 MIMO on 93 % of subframes). |
| Band 3 main carrier, −104 to −108 dBm | The second antenna reads 13–17 dB lower (bent antenna): rank 1, no MIMO on band 3. Uplink power-limited 50–78 % even at 2 Mbit/s (path loss 116 dB, requested 31 dBm). |
| Handover | Band 20 → band 8: 21 ms. |
| Uplink queue | 2.2 KB at 2 Mbit/s, 11–12 KB at 8 Mbit/s on a clean link (bursts to 60 KB). |

---

## How the EP06 differs

It logs newer versions of most packets. Each was decoded against known values (`AT+QRSRP`,
`AT+QENG="servingcell"`, `AT+QCAINFO`, uploads at a known 2 and 8 Mbit/s, the bytes the PC received at 3, 15 and
74 Mbit/s):

| Packet | EP06 version | What changed |
|---|---|---|
| 0xB193 serving cell | inner v22 | A cell-count word before the cell; one record per carrier (cell index 0 = main, 1 = second). Antenna RSRP matched `AT+QRSRP` within 0.5 dB. |
| 0xB173 PDSCH | v24 | One 24-byte record per carrier and subframe: resource blocks, TB count (MIMO), carrier index, 8-byte TBs. HARQ state is kept per carrier. |
| 0xB139 PUSCH | v102 | 68-byte records; TB size in bytes; no code-rate field (`ul_coderate` is worked out from TB size, resource blocks and modulation). |
| 0xB064 MAC UL TB | block v2 | The same fields two bytes further on. |
| 0xB066 UL buffer | block v24 | A pad byte after the sample count and after each sample. |
| 0xB16B PHICH | v25 | 80-byte records; ACK bit moved (checked against the retransmission rate); PDCCH entries of 8 bytes. |
| 0xB16E power control | v25 | Same records as v5. |
| 0xB067 UL Tx stats | v2 | The two counters one byte further on (within 1 % of the MAC totals). |
| 0xB14D CSI | v101 | Reports for both carriers; `cqi0`/`cqi1`/`ri` use the main carrier's; rank in a new place. No AT readout to check CQI against. |
| 0xB0B4 PDCP UL | block v24 | Same records as v3. |
| 0xB0C0 RRC | v13 | Channel numbers one lower than from v15 on (the SIM7600 sends v20). |
| 0xB097 RLC UL | | Logged only now and then: `rlc_ul_*` are NA most of the time. |

---

## Known issues

- **Trigger and the second carrier.** With two carriers the network also sends A1/A2 rules on the second
  carrier's frequency. The trigger names them `A2@<earfcn>` and evaluates them on that carrier; `modem_alink`'s
  edge hold ignores them (the second carrier only carries downlink).
- **CQI per carrier** is an assumption (reports alternate between two groups; rank reports only come in one).
- **Antenna:** on band 3 one antenna was 13–17 dB down (bent antenna): no MIMO on band 3.
- **One garbage queue sample of ~4 GB** could appear during a band search in older builds (same buffer decoder as
  the SIM7600); negative buffer samples are now dropped. Every fifth line was also ~20 % high because of the AT
  polls, fixed too (see the SIM7600 readme).
- **Trigger fields need the start of the connection**, as on every modem.

---

## Running it

```
modem_link [interval_s] [diag_port] [at_port] [--table]
```

| Argument | Default | Meaning |
|---|---|---|
| `interval_s` | `1` | Length of one output interval in seconds. The drone uses `0.25` (`S92modemlink`) so `modem_alink` can react within a quarter second. |
| `diag_port` | `/dev/ttyUSB0` | The modem's DIAG port. Only one program can read it at a time. |
| `at_port` | `/dev/ttyUSB2`, else `/dev/ttyUSB3` | AT port for the model name, temperature and supply voltage. If ModemManager holds it, those fields are NA; everything else still works. |
| `--table` | off | Prints the old human-readable column view instead of key=value lines. |

Ctrl-C (or SIGTERM) stops it and prints the [summary line](#summary-line).

**Outputs.** Every key=value line goes to:

- stdout;
- UDP `GROUND_IP:2224` from `/etc/masina.conf`, the same port as the SSC telemetry of `masinatelemetry` (the ground station tells them apart by the first field, the model name);
- UDP `127.0.0.1:2225` for `modem_alink` (nothing happens if it isn't running);
- with `DEBUG=2` in `/etc/masina.conf`: appended to `/mnt/mmcblk0p1/modem_link_<date>_<time>.log` if the SD card is mounted read-write.

**On the drone** `S92modemlink` starts it with `0.25` when `enabled=true` in `/etc/masina.conf`, and `S93modemalink`
starts `modem_alink`.

Start `modem_link` before the modem connects to the network. The handover rules (`meas_config`, the
[trigger fields](#trigger-the-networks-handover-rules)) are only known from messages it sees go by; if it starts in
the middle of a connection they stay unknown (`trigger=NA`) until the network sends new rules.

---

---

## Line format

```
EP06;time=21:32:36;dl_tbs=619;dl_bler=6.8%;...;rsrp0=-92.3dBm;rsrp1=-90.2dBm;...;scc_rsrp=-105.3dBm;...;t310=0
```

- The first field is the modem model (from `AT+CGMM`, e.g. `SIM7600G-H`, `EC25`, `EP06`).
- Then `name=value` pairs separated by `;`, **always the same fields in the same order**, so a parser can go by name
  or by position.
- Values carry their unit: `Mbps`, `%`, `dBm`, `dB`, `KB`, `ms`, `C`, `V`. Counts and indexes have none.
- `NA` means there was no data for that field in this interval (for example no uplink traffic, no neighbour measured,
  the AT port busy, the radio link down).
- Values are averaged over the interval unless the field says otherwise (`_max`, `_min`, counts).
- [Event lines](#events) have `event=<name>` as their third field and come between interval lines.
- The [summary line](#summary-line) (`event=summary`) is printed once on exit.

---

---

## Interval fields

In output order. "Source" names the DIAG log packet ([table](#where-the-values-come-from)).

### time

| Field | Meaning |
|---|---|
| `time` | Local time (HH:MM:SS) at the end of the interval. |

### Downlink (tower → modem)

Source: PDSCH statistics (0xB173). Only data for this modem (C-RNTI) counts; system information and paging are left
out.

| Field | Unit | Meaning | How to read it |
|---|---|---|---|
| `dl_tbs` | count | Downlink transport blocks received (new + HARQ retransmissions). | 0 = no downlink scheduled. |
| `dl_bler` | % | Share of **first** transmissions that failed CRC. | The network aims at ~10 %. Much higher = poor radio or link adaptation lagging. |
| `dl_harq_retx` | count | HARQ retransmissions received. | |
| `dl_harq_retx_pct` | % | Retransmissions as a share of all TBs. | |
| `dl_resid` | count | TBs that HARQ gave up on (the next new TB on that HARQ process arrived before the old one decoded). | Not zero = RLC has to recover the data: extra delay, possibly loss. |
| `dl_mcs` | | Mean MCS (0–28) of new TBs. | 0–9 QPSK, 10–16 16QAM, 17–28 64QAM. Higher = better radio. |
| `dl_rbs` | | Mean resource blocks per scheduled subframe. | 50 = a full 10 MHz carrier, 100 = 20 MHz. Low with high demand = the cell is shared/loaded. |
| `dl_mimo` | % | Share of new-data subframes that carried 2 codewords (2×2 spatial multiplexing), both carriers. | 0 % = rank 1 only (weak signal, or one antenna poor). |
| `dl_rate` | Mbps | Downlink goodput at the physical layer: bytes of TBs that passed CRC, both carriers. | Includes RLC/PDCP/IP headers, so a few % above what an application sees. |
| `dl_scc_rate` | Mbps | The part of `dl_rate` that came over the second carrier (carrier aggregation). | NA without a second carrier. |
| `pdcch_agg` | | Mean PDCCH aggregation level (1, 2, 4 or 8) of the scheduling messages. Source: PHICH log (0xB16B). | 1 = good. The network raises it to protect the control channel when the radio is poor; 4–8 right before a drop was seen on the SIM7600 basement walk. |

### Uplink transmission (modem → tower)

| Field | Unit | Source | Meaning | How to read it |
|---|---|---|---|---|
| `ul_tx` | count | PUSCH tx (0xB139) | Uplink transmissions (new + retransmissions). | |
| `ul_harq_retx` | count | PUSCH + MAC UL | Retransmissions: a PUSCH with no new MAC transport block, 8 ms after an earlier transmission (synchronous FDD HARQ). | |
| `ul_harq_retx_pct` | % | | Retransmissions as a share of `ul_tx`. | A few % is normal; 10 %+ = uplink struggling. |
| `ul_nack` | count | PHICH (0xB16B) | NACKs the tower sent back for uplink transmissions. | Direct sign of uplink decode failures. |
| `ul_nack_pct` | % | | NACKs as a share of all PHICH answers. | |
| `ul_rate` | Mbps | MAC UL TB (0xB064) | Uplink goodput at the MAC layer: bytes of new transport blocks minus padding. **This is what the uplink actually carried.** | `modem_alink` uses it as the link's capacity while a queue is waiting. |
| `ul_grant` | Mbps | MAC UL Tx stats (0xB067) | Uplink capacity the tower granted. | Grant ≫ `ul_rate` = the modem had less to send than it was offered. |
| `ul_grant_used` | % | | Share of granted bytes filled with data (the rest is padding). | ~100 % with a queue waiting = the grant is the bottleneck. |
| `ul_rbs` | | PUSCH tx | Mean resource blocks per uplink transmission. | |
| `ul_mod` | | PUSCH tx | Most used uplink modulation in the interval: `QPSK`, `16QAM`, `64QAM`. | The EP06 uses 64QAM at good signal. |
| `ul_coderate` | | PUSCH tx | Mean coding rate (0–1), worked out from TB size, resource blocks and modulation. | Higher = more data per resource block. |

### Uplink power

| Field | Unit | Source | Meaning | How to read it |
|---|---|---|---|---|
| `ul_pwr` | dBm | PUSCH tx | Mean **requested** PUSCH power: what power control asks for. | Can exceed 23 dBm. |
| `ul_txpwr` | dBm | PUSCH power control (0xB16E) | Mean **actual** transmit power. | The EP06's maximum is 23 dBm. |
| `ul_pwrlim` | % | PUSCH tx | Share of transmissions where the requested power was above 23 dBm, i.e. the modem was **power-limited**. | 0 % = power to spare. High = cell edge: the uplink can't carry more however long you wait. |
| `ul_pc_corr` | dB | PUSCH power control | Closed-loop power control correction f(i): sum of the tower's "more/less power" commands. | Strongly positive = the tower keeps asking for more power. |
| `pathloss` | dB | PUSCH power control | Downlink path loss the modem estimates (reference signal power − RSRP). | ~110 dB close to the tower, 130–140 dB at the edge. |
| `phr` | dB | MAC control element (0xB064) | Power headroom the modem reports to the tower: how much below its maximum it transmits. | Negative = power-limited. |

### Uplink queue

The most important group for video: it shows data waiting **inside the modem** before the radio sends it.

| Field | Unit | Source | Meaning | How to read it |
|---|---|---|---|---|
| `ul_buf` | KB | MAC UL buffer status (0xB066), one sample per millisecond | Mean bytes queued in the modem's uplink buffer. | ~0 when the link keeps up. |
| `ul_buf_max` | KB | | Largest queue of the interval. | Video keyframes make short spikes here. |
| `ul_buf_min` | KB | | Smallest queue of the interval: the **standing queue**. | Above 0 = the queue never emptied: the link carries less than is sent. Keyframe spikes don't raise it. |
| `bsr` | KB | MAC control element (0xB064) | Buffer Status Report the modem sends to the tower (quantized). | Tops out at 150 KB. Used for the queue fields when the modem doesn't log 0xB066. |
| `qdelay` | ms | | Mean queue delay: mean queue ÷ uplink rate (`ul_rate`, floored at 0.5 Mbit/s so an idle link doesn't divide by ~0). | How long a new packet waits in the modem on average. |
| `qdelay_max` | ms | | Largest queue ÷ uplink rate. | |
| `qdelay_min` | ms | | Standing queue ÷ uplink rate. **`modem_alink` cuts the bitrate on this.** | > 0 steadily = congestion; brief spikes don't count. |
| `qwarn` | 0/1 | | 1 when `qdelay` ≥ 50 ms with at least 10 KB queued. | In UDP tests, loss followed 1–2 s after it. |

### RLC / PDCP counters

How much each counter **increased** during the interval, over all radio bearers. The modem logs these statistics
only about every 1.3 s, so at short intervals most lines show `NA`.

| Field | Meaning |
|---|---|
| `rlc_ul_retx` | Uplink RLC PDUs retransmitted (the tower asked for them again). |
| `rlc_ul_nack` | NACKs received from the tower in RLC status reports. |
| `rlc_ul_tpoll` | Expiries of the RLC poll-retransmit timer (the tower didn't answer a poll in time). |
| `rlc_dl_retx` | Downlink RLC PDUs received again (retransmissions). |
| `rlc_dl_nack` | NACKs the modem sent for missing downlink RLC PDUs. |
| `rlc_dl_drop` | Downlink RLC PDUs dropped (duplicates or outside the window). |
| `rlc_dl_treord` | t-Reordering expiries: the modem gave up waiting for a missing downlink PDU. |
| `pdcp_ul_discard` | Uplink PDCP packets the modem **discarded** because they waited too long (PDCP discard timer). Not zero = uplink data was thrown away inside the modem. |

On the EP06 the RLC uplink statistics only arrive now and then, so `rlc_ul_*` are NA most of the time.

These all stay 0 on a clean link. HARQ (fast, per transmission) catches nearly everything; RLC is the slower second line.

### Channel quality reports

Source: PUCCH CSI reports (0xB14D), what the modem tells the tower about the downlink. On the EP06 these are the
main carrier's reports.

| Field | Meaning | How to read it |
|---|---|---|
| `cqi0` | Mean wideband CQI for codeword 0 (0–15). | Roughly tracks SINR: 15 = best. |
| `cqi1` | Mean CQI for codeword 1, only reported at rank 2. | NA at rank 1. |
| `ri` | Mean rank indicator (1–2): how many streams the modem asks for. | 2 = both antennas usable for MIMO. |

### Modem health

Polled over AT every 5 s.

| Field | Unit | Meaning |
|---|---|---|
| `temp` | C | Modem temperature (SIMCom `AT+CPMUTEMP`, Quectel `AT+QTEMP`: the hottest of its sensors). |
| `vbat` | V | Supply voltage at the modem (`AT+CBC`). Dips under transmit load point to a weak supply. |

### Serving cell

Source: serving cell measurement (0xB193), about 50 samples a second, averaged. **Main carrier only**; the
second carrier has its own fields below.

| Field | Unit | Meaning | How to read it |
|---|---|---|---|
| `earfcn` | | Downlink channel number of the serving cell. It gives the band: 1200–1949 = band 3 (1800 MHz), 3450–3799 = band 8 (900 MHz), 6150–6449 = band 20 (800 MHz). | Here: 1850 = band 3, 3500 = band 8, 6400 = band 20. |
| `pci` | | Physical cell ID (0–503) of the serving cell. | Same tower, different band = usually the same PCI (186 here). Neighbouring PCIs (187) are often other sectors. |
| `rsrp0` | dBm | Reference signal received power on RX antenna 0. | > −90 excellent, −90 to −105 good, −105 to −115 fair, −115 to −120 poor, < −120 cell edge. |
| `rsrp1` | dBm | Same on RX antenna 1 (diversity). | |
| `rsrp_diff` | dB | `rsrp0 − rsrp1`. | More than ~6–10 dB = an antenna or cable problem, or a strongly orientation-dependent setup. |
| `snr0`, `snr1` | dB | Signal-to-noise per antenna (approximate). | Above ~15 dB good, below 0 the link is about to fail. |
| `rsrq` | dB | Reference signal received quality, combined. | > −10 good, −10 to −15 fair, < −15 poor (interference or a loaded cell). |
| `rssi` | dBm | Total received power, both antennas, including interference and other users' traffic. | |

### Neighbour cells

Source: intra-frequency (0xB179) and all-frequency (0xB195) neighbour measurements. Cells on other bands are only
measured while the network has measurement gaps on, i.e. while it is searching. The second carrier is left out
(it is no handover candidate).

| Field | Unit | Meaning | How to read it |
|---|---|---|---|
| `ncells` | count | Neighbour cells measured in the interval. | |
| `nb_earfcn` | | Channel of the strongest neighbour. | |
| `nb_pci` | | Its physical cell ID. | |
| `nb_rsrp` | dBm | Its RSRP. | |
| `nb_rsrq` | dB | Its RSRQ. | |
| `ho_margin` | dB | Serving RSRP − strongest neighbour RSRP. | Small or negative = a stronger cell exists. Whether a handover happens is the network's decision, by its own rules: see the trigger fields. |

### Second carrier (carrier aggregation)

| Field | Unit | Meaning |
|---|---|---|
| `scc_earfcn` | | Channel of the second carrier (from its own serving measurement, else `AT+QCAINFO`). |
| `scc_pci` | | Its physical cell ID. |
| `scc_rsrp` | dBm | Its RSRP (better antenna), from its serving measurement while it is active (about 1,000 samples a second), else the neighbour measurement of it, else `AT+QCAINFO`. |
| `scc_rsrq` | dB | Its RSRQ, same sources. |
| `scc_sinr` | dB | Its SINR as the modem reports it in `AT+QCAINFO` (polled every 5 s). |

All NA without a second carrier.

### Trigger: the network's handover rules

The network sends the modem its measurement rules (see [`meas_config`](#meas_config)). The trigger fields show the
rule **closest to firing**, evaluated the way the modem does: on the filtered serving RSRP (0xB179) and the latest
neighbour measurements. They answer "is a band search, a handover or a release about to happen, and how far away is
it".

| Field | Unit | Meaning |
|---|---|---|
| `trigger` | | The rule closest to firing: `A1`, `A2`, `A3@3500`, `A5@1875/3500/6400`, … Rules with the same condition on several frequencies are shown as one. `NA` = no rules known (not connected, or `modem_link` started mid-connection). |
| `trigger_gap` | dB | How far the signal can still move before the rule's condition holds. **≤ 0 = it holds now.** For a rule that needs a neighbour that hasn't been measured yet (a cell on another band, before the search runs), only the serving part counts, and the value stops at 0. |
| `trigger_nb` | dBm | The neighbour the rule compares against (A3/A4/A5). `NA` = not measured yet. |
| `trigger_held` | ms | How long the condition has held without a break. |
| `trigger_ttt` | ms | The rule's time-to-trigger. The modem sends its report when `trigger_held` reaches this, and the network acts on the report (usually within milliseconds). |

With two carriers the network also sends A1/A2 rules on the second carrier's frequency: they show as
`A2@<earfcn>` and are evaluated on that carrier.

What the rule types mean is in [Rule syntax](#rule-syntax). What usually follows:

- **A2** firing → the network starts a search for other bands (gaps on), or with a low last-resort threshold, releases the connection.
- **A1** firing → the signal is good again, the search stops.
- **A3/A5** firing → handover to the cell that met the rule.

### Radio link monitoring

Source: radio link monitoring (0xB18A).

| Field | Unit | Meaning | How to read it |
|---|---|---|---|
| `rlm_oos` | % | The modem's estimate of the downlink control channel's block error rate (out-of-sync). | High = the downlink is close to unusable. |
| `t310` | 0/1 | 1 if the T310 timer ran in the interval: the modem lost sync with the cell. | If it doesn't recover before T310 expires (typically 1 s), a radio link failure follows (`reestablishment` event). |

---

---

## Events

Printed the moment they happen, with the exact time (milliseconds):

```
EP06;time=20:56:14.523;event=handover;from_pci=186;from_earfcn=6400;to_pci=186;to_earfcn=3500
```

Except `cell_change`, they come from the RRC messages between modem and network (0xB0C0) and the random-access
logs (0xB061/0xB062).

### rrc_setup

The modem connected (left idle).

| Field | Meaning |
|---|---|
| `cause` | Why: `mo-Data` (the modem has data to send), `mt-Access` (the network paged it), `mo-Signalling`, `emergency`, `highPriorityAccess`, `delayTolerantAccess`, `mo-VoiceCall`. |
| `pci`, `earfcn` | Cell it connected on. |

### rrc_release

The network ended the connection.

| Field | Meaning |
|---|---|
| `cause` | `other` (normal end after inactivity, or a release at the cell edge), `loadBalancingTAUrequired`, `cs-FallbackHighPriority`, `rrc-Suspend`. |
| `connected` | How long the connection lasted, or `NA` if `modem_link` didn't see it start. |
| `pci`, `earfcn` | Cell it was on. |

A release after inactivity is normal. A release right after a last-resort A2 report, while traffic is flowing, is a
**drop**: the modem then has no service until it finds a cell again (39 s on the SIM7600 basement walk).

### rrc_reject

The network refused a connection request (`pci`, `earfcn`). Usually overload.

### meas_config

The network sent new measurement (handover) rules. Printed only when the set of rules changes.

| Field | Meaning |
|---|---|
| `rules` | All active rules, comma-separated: `<measId>:<rule>@<frequency>`. See [Rule syntax](#rule-syntax). `none` = no rules (right after a handover command, the new cell's rules follow). |
| `gaps` | Measurement gaps: `gp0:<offset>` (6 ms every 40 ms) or `gp1:<offset>` (6 ms every 80 ms) when the modem may listen to other frequencies, `off` otherwise. Gaps on = the network is searching other bands; uplink and downlink pause during the gaps. |
| `known` | `full` if `modem_link` saw the connection start and every rule since; `partial` if some rules were sent before it started (they show as `?`). |

#### Rule syntax

Each rule is `<measId>:<event>[<condition>,hys<dB>,ttt<ms>]@<frequency>`.

| Event | Condition (as printed) | Fires when |
|---|---|---|
| `A1` | `serving>rsrp-114dBm` | the serving cell gets **better** than the threshold (plus hysteresis) |
| `A2` | `serving<rsrp-118dBm` | the serving cell gets **worse** than the threshold (minus hysteresis) |
| `A3` | `nb>serving+3dB` | a neighbour on the same frequency gets better than the serving cell by the offset (plus hysteresis) |
| `A4` | `nb>rsrp-110dBm` | a neighbour gets better than the threshold |
| `A5` | `serving<rsrp-115dBm&nb>rsrp-113dBm` | the serving cell is worse than threshold 1 **and** a neighbour is better than threshold 2 |
| `B1` | `irat>…` | a 3G/2G cell gets better than a threshold |
| `B2` | `serving<…&irat>…` | serving worse than threshold 1 and a 3G/2G cell better than threshold 2 |
| `periodic[strongest]` | | periodic reports of the strongest cells |
| `periodic[cgi]` | | the network wants a neighbour's global cell ID |
| `ext<n>` | | a newer event type, not decoded |

- Thresholds are `rsrp<dBm>` or `rsrq<dB>`.
- `hys` is the hysteresis: an A2 at −114 dBm with `hys2dB` fires below −116 dBm.
- `ttt` is the time-to-trigger: how long the condition must hold.
- `@3500` is the frequency (EARFCN) the rule measures; `@utra10700` / `@geran20` are 3G/2G; `@?` means the rule
  was set up before `modem_link` started.

Example from the SIM7600 walk (band 3 fading): the network answered an A2 report with
`9:A2[serving<rsrp-118dBm,hys2dB,ttt40ms]@?,10:A1[serving>rsrp-114dBm,hys2dB,ttt640ms]@?,11:A5[serving<rsrp-115dBm&nb>rsrp-113dBm,hys1dB,ttt480ms]@1875,12:A5[...]@3500,13:A5[...]@6400`,
i.e. "search band 3 (1875), band 8 (3500) and band 20 (6400); hand over to any cell above −112 dBm while serving is
below −116 dBm; stop searching if serving recovers above −112 dBm".

### meas_report

The modem reported to the network that a rule fired.

| Field | Meaning |
|---|---|
| `rule` | `<measId>:<event>@<frequency>` of the rule that fired, e.g. `12:A5@3500`. |
| `srv_rsrp`, `srv_rsrq` | Serving cell as the modem reported it (whole dB). |
| `cells` | Reported neighbours as `<pci>:<rsrp>:<rsrq>`, comma-separated, or `none`. |

A report with `cells=none` from an A2 means "my serving cell is weak": the network usually turns on a search next.
A report with a neighbour from A3/A5 is normally followed by a `handover` within milliseconds.

### handover

The network ordered a handover.

| Field | Meaning |
|---|---|
| `from_pci`, `from_earfcn` | Cell it leaves. |
| `to_pci`, `to_earfcn` | Target cell. A different EARFCN with the same PCI = a band change on the same tower. |

### handover_done

The modem confirmed the handover on the new cell.

| Field | Meaning |
|---|---|
| `pci`, `earfcn` | The new cell. |
| `duration` | Time from the handover command to the confirmation. 20–40 ms is typical; the data pause is about that long. |

### rach

A random access on the uplink (how the modem gets in contact with a cell).

| Field | Meaning |
|---|---|
| `reason` | `connection` (from idle), `handover`, `ul_data` (uplink data while out of uplink sync or without a scheduling resource), `dl_data` (the network asked for it to send downlink data), `rlf` (after a radio link failure). |
| `result` | `success`, `msg2_fail` (no answer from the cell), `aborted`. |
| `contention` | `free` (the network reserved a preamble, e.g. in a handover) or `based`. |
| `ta` | Timing advance in steps. |
| `distance` | Distance to the tower from the timing advance (one step = 78.1 m). |

### reestablishment, reestablishment_done, reestablishment_reject

`reestablishment`: the radio link failed and the modem tries to re-establish the connection.

| Field | Meaning |
|---|---|
| `cause` | `otherFailure` (radio link failure), `handoverFailure`, `reconfigurationFailure`. |
| `failed_pci` | The cell where the link failed. |
| `pci`, `earfcn` | The cell it tries now. |

`reestablishment_done` = it worked, data continues. `reestablishment_reject` = it didn't; the modem goes idle and
must connect anew.

### cell_change

Printed by `modem_link` itself when the serving cell (EARFCN/PCI) differs from the previous interval:
`earfcn_old`, `pci_old`, `earfcn`, `pci`. It also catches cell changes while idle, when no RRC messages are logged.

---

## Summary line

Printed once when `modem_link` stops: `<model>;event=summary;...`

| Field | Meaning |
|---|---|
| `duration` | Seconds measured. |
| `dl_total`, `dl_avg`, `dl_peak` | Downlink bytes (MB), average and best interval (Mbps). |
| `dl_bler`, `dl_harq_retx`, `dl_harq_retx_pct`, `dl_resid` | As the interval fields, over the whole run. |
| `ul_total`, `ul_avg`, `ul_peak` | Uplink bytes (MB), average and best interval (Mbps). |
| `ul_harq_retx`, `ul_harq_retx_pct`, `ul_nack`, `ul_nack_pct`, `ul_pwrlim`, `ul_grant_used` | As the interval fields, over the whole run. |
| `pathloss_min`, `pathloss_max` | Range of the path loss. |
| `ul_buf_max`, `qdelay_max` | Largest uplink queue and queue delay of any interval. |
| `qwarn_intervals` | Intervals with `qwarn=1`. |
| `intervals` | Number of interval lines. |
| `rlc_ul_retx`, `rlc_ul_nack`, `rlc_dl_retx`, `rlc_dl_nack`, `rlc_dl_drop`, `pdcp_ul_discard` | Totals of the RLC/PDCP counters. |
| `t310_intervals` | Intervals where T310 ran. |
| `rrc_setups`, `rrc_releases`, `meas_reports`, `handovers`, `handovers_done`, `reestablishments` | Event counts. |
| `temp_min`, `temp_max`, `vbat_min`, `vbat_max` | Range of the modem temperature and supply voltage. |

---

---

## Reading the link

- **Link keeping up:** `ul_buf_min`/`qdelay_min` ≈ 0, `qdelay` low, `ul_pwrlim` ~0 %.
- **Congestion (sending more than the link carries):** `qdelay_min` > 0 and rising, `ul_buf_min` > 0, `ul_grant_used`
  ~100 %, `ul_rate` flat at its ceiling. Lower the bitrate (this is what `modem_alink` does).
- **Keyframe spikes, no congestion:** `ul_buf_max`/`qdelay_max` jump but `ul_buf_min`/`qdelay_min` stay ~0. Nothing to do.
- **Cell edge (uplink short of power):** `ul_pwrlim` high, `ul_txpwr` 22–23 dBm, `phr` ≤ 0, path loss > 130 dB,
  RSRP < −115 dBm. The uplink capacity is falling; a queue follows quickly.
- **Antenna problem:** `rsrp_diff` large and steady (> 6–10 dB), `dl_mimo` ~0 %, `ri` stuck at 1.
- **Handover coming:** `trigger` = an A3/A5 with `trigger_gap` ≤ 0 and `trigger_held` approaching `trigger_ttt`.
  Usually harmless (tens of ms).
- **Drop coming:** an A2 report, a search (`gaps` on) that ends without a handover, then only a low A2 left and
  `trigger_gap` near 0, `t310=1`, `rlm_oos` high.
- **After a drop:** the reconnect (`rrc_setup`) can be followed by a burst (`ul_buf_max` hundreds of KB): old data the
  modem kept through the outage.

---
- **Two carriers:** `dl_scc_rate` > 0 = the second carrier carries part of the downlink. The uplink always
  rides on the main carrier alone, so a weak main carrier limits the uplink even when the second one is strong.

---

## modem_alink

Sets the camera's encoder bitrate over its HTTP API (`/api/v1/set?video0.bitrate=<kbit/s>`, and `video0.fps` below
1 Mbit/s) from `modem_link`'s lines on `127.0.0.1:2225`. It decides on every line, so at `modem_link 0.25` it reacts
within a quarter second.

**How it decides:**

- **Congested** = a standing queue: `qdelay_min` at or above the preset's threshold with at least `qbytes_min` still
  queued (or `queue_min` ≥ `qbytes_high`). Then it aims for a share (`ul_share`) of what the uplink carried
  (`ul_rate`), minus enough to empty the queue within `drain` seconds, and cuts toward that (at least to
  `down_factor` of the bitrate, at most to `cut_floor` of it per line).
- **Clear** = `qdelay_min` below the preset's clear threshold: after `up_after` seconds clear it raises a step per
  line, gently while within 10 s of the last congestion, up to the preset's maximum.
- **Edge:** the `trigger` is within 2 dB of firing (search, handover or release; not A1, and not an A2 about the
  second carrier, `A2@<other EARFCN>`): no raising.
- **Handover / service back:** for 1 s after the serving cell changes, no cuts (the queue the switch built drains on
  the new cell).
- **No service** (no serving cell in the line): no raising.
- Lines from an older `modem_link` without `qdelay_min` fall back to the interval average.
- Below 1 Mbit/s the frame rate goes down too: 40, 30, then 20 fps.

**Presets:**

| Preset | Max bitrate | Congested at `qdelay_min` ≥ | Clear below | Raise |
|---|---|---|---|---|
| `performance` | 4000 kbit/s | 10 ms with ≥ 5 KB queued (or ≥ 50 KB) | 3 ms | ~3 %/s |
| `balanced` | 8000 kbit/s | 20 ms with ≥ 10 KB queued (or ≥ 100 KB) | 5 ms | ~5 %/s |
| `quality` | 16000 kbit/s | 40 ms with ≥ 20 KB queued | 10 ms | ~8 %/s |

**Output.** Every change is printed and sent to `GROUND_IP:2224`. Example from the SIM7600 basement walk replayed into
it, at the cell edge while the network searched other bands:

```
ALINK;time=17:32:54;enabled=1;preset=balanced;bitrate=2840kbps;max=8000kbps;fps=60;prev=5680kbps;reason=congestion;qdelay=610ms;queue=38.1KB;ul_rate=0.41Mbps;qdelay_min=565ms;queue_min=35.3KB;trigger=A5@1850/1875/6400;trigger_gap=0.0dB
```

| Field | Meaning |
|---|---|
| `enabled` | 1 = it controls the bitrate. |
| `preset` | Active preset. |
| `bitrate`, `prev` | Bitrate after and before this change (kbit/s). |
| `max` | The preset's maximum. |
| `fps` | Current frame rate. |
| `reason` | Why (below). |
| `qdelay`, `queue`, `ul_rate`, `qdelay_min`, `queue_min`, `trigger`, `trigger_gap` | The `modem_link` values it decided on. |

| Reason | Meaning |
|---|---|
| `start` | Took over the camera (its bitrate and fps are what gets given back later). |
| `max` | Capped at the preset's maximum. |
| `congestion` | Cut because of a standing queue. |
| `recover` | Raised because the queue stayed clear. |
| `edge` | A network rule is about to fire: raising paused (no bitrate change). |
| `handover` | The serving cell changed: 1 s without cuts. |
| `no_service` | No serving cell (link down): raising paused. |
| `service` | Serving cell back after an outage: 1 s without cuts. |
| `fps` | Frame rate changed. |
| `external` | Someone else changed the bitrate (e.g. the ground station's slider); it carries on from there. |
| `no_data` | No `modem_link` lines for 3 s: bitrate held. |
| `preset` | Preset changed. |
| `enable`, `disable` | Switched on or off (on disable it gives the camera back its own bitrate and fps). |
| `exit` | Stopped (gives the camera back). |

**Settings** (`/etc/masina.conf`): `ALINK_ENABLED=true|false` (default true), `ALINK_PRESET` (default `balanced`),
`ALINK_CAMERA=host[:port]` (default `127.0.0.1:80`), `ALINK_MIN_BITRATE` (kbit/s, default 1),
`ALINK_CONTROL_PORT` (default 2226), `GROUND_IP`.

**Control** on port 2226, HTTP or UDP, answers with a status line:

```
curl 'http://<drone>:2226/?preset=performance&enable=1'
echo 'preset=quality;enable=1' | nc -u -w1 <drone> 2226
```

---

---

## Where the values come from

DIAG log packets `modem_link` subscribes to; the EP06's versions are in [How the EP06 differs](#how-the-ep06-differs):

| Code | Name | Gives |
|---|---|---|
| 0xB173 | PDSCH statistics | Downlink TBs, BLER, HARQ, MCS, RBs, MIMO, `dl_rate` |
| 0xB139 | PUSCH Tx report | Uplink transmissions, RBs, modulation, coding rate, requested power |
| 0xB064 | MAC UL transport block | `ul_rate`, BSR, PHR |
| 0xB066 | MAC UL buffer status | `ul_buf` (exact queue, every millisecond) |
| 0xB067 | MAC UL Tx statistics | `ul_grant`, `ul_grant_used` |
| 0xB16B | PDCCH/PHICH | `ul_nack`, `pdcch_agg` |
| 0xB16E | PUSCH power control | `ul_txpwr`, `pathloss`, `ul_pc_corr` |
| 0xB14D | PUCCH CSI report | `cqi0`, `cqi1`, `ri` |
| 0xB193 | Serving cell measurement | `earfcn`, `pci`, RSRP/SNR per antenna, RSRQ, RSSI; `scc_*` of the second carrier |
| 0xB179 | Intra-frequency neighbour measurement v4 | Neighbours, filtered serving RSRP (trigger) |
| 0xB195 | Connected-mode neighbour measurement | Neighbours on every measured frequency |
| 0xB18A | Radio link monitoring v1 | `rlm_oos`, `t310` |
| 0xB087, 0xB097, 0xB0B4 | RLC DL, RLC UL, PDCP UL statistics | RLC/PDCP counters |
| 0xB0C0 | RRC OTA message | All events except `cell_change` and `rach` |
| 0xB061, 0xB062 | RACH trigger / attempt | `rach` events |

---

---

## Other modems

- [README_SIM7600.md](README_SIM7600.md): SIMCom SIM7600G-H, the modem these tools were built on.
- [README_EC25.md](README_EC25.md): Quectel EC25, same chipset family as the SIM7600.
