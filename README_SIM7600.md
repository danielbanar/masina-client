# SIMCom SIM7600G-H

LTE Cat 4 module with a Qualcomm MDM9607 inside. `modem_link` and `modem_alink` were built on it, so every field and event in this document is decoded on it. This readme covers what the modem can do, how it is set up, real output from it, and the full reference of `modem_link`'s fields and events.

- [Capabilities](#capabilities)
- [Setup](#setup)
- [Example output](#example-output)
- [Measured on this setup](#measured-on-this-setup)
- [Verified on this modem](#verified-on-this-modem)
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
| Module | SIMCom SIM7600G-H (global variant), firmware LE20B04SIM7600G22 |
| Chipset | Qualcomm MDM9607 (DIAG build MPSS.JO.2.0.2) |
| LTE category | Cat 4: up to 150 Mbit/s down, 50 Mbit/s up |
| Bands | The band preference (`AT+CNBP?`) allows LTE 1–14, 17–21, 23–43, 66 and 71, plus 3G/2G (`AT+CNMP?` = 2, automatic). Seen here: band 3 (1800 MHz, 20 MHz wide), 8 (900 MHz, 10 MHz wide), 20 (800 MHz, 10 MHz wide); `AT+CPSI?` gives the band and the width. |
| Carrier aggregation | No: one carrier at a time |
| MIMO | 2×2 downlink (two receive antennas, rank 1 or 2) |
| Uplink | QPSK and 16QAM, 23 dBm maximum |
| USB | `1e0e:9011`, RNDIS network interface: the modem dials and routes by itself, DHCP gives 192.168.225.x |
| Serial ports | `ttyUSB0` DIAG, `ttyUSB1` GPS (NMEA), `ttyUSB2` AT, `ttyUSB3` AT / PPP, `ttyUSB4` audio |
| Useful AT commands | `AT+CPSI?` serving cell, `AT+CNBP?` band preference, `AT+CNMP?` network mode, `AT+CPMUTEMP` temperature, `AT+CBC` supply voltage |
| What `modem_link` decodes | Everything: every field and event in this document |
| DIAG log versions | serving cell v18, PDSCH v5, PUSCH v25, PHICH v5, power control v5, CSI v24, UL buffer v5, MAC UL TB v1, RRC v20 |

---

## Setup

**On this PC** the modem is kept away from ModemManager and NetworkManager and brought up with ifupdown:

- `/etc/udev/rules.d/77-sim7600.rules`: ModemManager ignores the modem; its network interface is meant to be
  named `usb0` and left alone by NetworkManager.
- `/etc/network/interfaces.d`: `iface usb0 inet dhcp` with `metric 100`.
- `sim7600.service` runs `ifup usb0` at boot.

The renaming line of that rule never matches: it combines `DRIVERS=="rndis_host"` (on the USB interface) with
`ATTRS{idVendor}` (on the USB device), and udev wants every such match on one device. So the interface keeps its
`enx<MAC>` name, which changes with every modem reset, and `ifup usb0` finds nothing. Replacing
`DRIVERS=="rndis_host"` with `SUBSYSTEMS=="usb"` in that line fixes it (as done in `78-ep06.rules` for the EP06).

**On the drone** `S92modemlink` starts `modem_link 0.25` and `S93modemalink` starts `modem_alink`; see
[Running it](#running-it).

---

## Example output

Real lines from the walks on 24 Oct 2026 (O2 Slovakia, tower about 1.2 km away). They were recorded with `lte_link`, the desktop twin of `modem_link` with the same decoder code, about an hour before the trigger fields existed. `modem_link` at this commit prints the same fields, plus `trigger`, `trigger_gap`, `trigger_nb`, `trigger_held` and `trigger_ttt` after `ho_margin` (see the EC25 and EP06 readmes for lines with them).

**Band 8, fair signal, 1 Mbit/s test upload:**

```
SIM7600G-H;time=17:03:44;dl_tbs=39;dl_bler=0.0%;dl_harq_retx=0;dl_harq_retx_pct=0.0%;dl_resid=0;dl_mcs=1.4;dl_rbs=3.4;dl_mimo=0%;dl_rate=0.01Mbps;pdcch_agg=1.00;ul_tx=305;ul_harq_retx=8;ul_harq_retx_pct=2.6%;ul_nack=7;ul_nack_pct=2.3%;ul_rate=1.06Mbps;ul_grant=1.26Mbps;ul_grant_used=82%;ul_rbs=10.9;ul_mod=16QAM;ul_coderate=0.84;ul_pwr=20.3dBm;ul_txpwr=18.4dBm;ul_pwrlim=28.2%;ul_pc_corr=-1.2dB;pathloss=117.7dB;ul_buf=1.3KB;ul_buf_max=2.5KB;ul_buf_min=0.0KB;bsr=1.0KB;qdelay=10ms;qdelay_max=19ms;qdelay_min=0ms;qwarn=0;phr=4dB;rlc_ul_retx=0;rlc_ul_nack=0;rlc_ul_tpoll=0;rlc_dl_retx=0;rlc_dl_nack=0;rlc_dl_drop=0;rlc_dl_treord=0;pdcp_ul_discard=0;cqi0=13.3;cqi1=9.0;ri=1.7;temp=39C;vbat=4.05V;earfcn=3500;pci=186;rsrp0=-105.0dBm;rsrp1=-103.1dBm;rsrp_diff=-1.9dB;snr0=15.2dB;snr1=14.1dB;rsrq=-6.9dB;rssi=-77.5dBm;ncells=1;nb_earfcn=3500;nb_pci=187;nb_rsrp=-117.5dBm;nb_rsrq=-22.8dB;ho_margin=15.4dB;rlm_oos=0%;t310=0
```

- Band 8 (`earfcn=3500`), cell 186, RSRP −105/−103 dBm on the two antennas, SNR 15/14 dB, rank 1.7.
- The 1 Mbit/s stream goes through (`ul_rate=1.06Mbps`) with 16QAM at 18.4 dBm; power-limited 28 % of the time.
- Queue 1.3 KB, 10 ms, no standing queue (`qdelay_min=0ms`): the link keeps up.

**Band 3, one second before a handover to band 8:**

```
SIM7600G-H;time=17:02:17;dl_tbs=45;dl_bler=0.0%;dl_harq_retx=0;dl_harq_retx_pct=0.0%;dl_resid=0;dl_mcs=3.4;dl_rbs=4.0;dl_mimo=0%;dl_rate=0.02Mbps;pdcch_agg=1.10;ul_tx=351;ul_harq_retx=30;ul_harq_retx_pct=8.5%;ul_nack=20;ul_nack_pct=5.9%;ul_rate=1.08Mbps;ul_grant=1.12Mbps;ul_grant_used=93%;ul_rbs=30.1;ul_mod=QPSK;ul_coderate=0.45;ul_pwr=36.8dBm;ul_txpwr=23.0dBm;ul_pwrlim=99.7%;ul_pc_corr=-2.7dB;pathloss=129.7dB;ul_buf=2.2KB;ul_buf_max=6.1KB;ul_buf_min=0.0KB;bsr=1.7KB;qdelay=16ms;qdelay_max=45ms;qdelay_min=0ms;qwarn=0;phr=-8dB;rlc_ul_retx=0;rlc_ul_nack=0;rlc_ul_tpoll=0;rlc_dl_retx=0;rlc_dl_nack=0;rlc_dl_drop=0;rlc_dl_treord=0;pdcp_ul_discard=0;cqi0=10.6;cqi1=9.8;ri=2.0;temp=38C;vbat=3.97V;earfcn=1850;pci=186;rsrp0=-117.9dBm;rsrp1=-114.2dBm;rsrp_diff=-3.7dB;snr0=5.3dB;snr1=10.5dB;rsrq=-14.0dB;rssi=-80.1dBm;ncells=1;nb_earfcn=1850;nb_pci=187;nb_rsrp=-130.5dBm;nb_rsrq=-23.9dB;ho_margin=16.5dB;rlm_oos=0%;t310=0
```

- RSRP −118/−114 dBm, SNR 5/10 dB, RSRQ −14 dB: band 3 is weak here.
- The uplink is at its limit: 23.0 dBm actual, 36.8 dBm requested, power-limited 99.7 %, headroom −8 dB, path
  loss 130 dB, QPSK. 1 Mbit/s still gets through, with 8.5 % HARQ retransmissions and 5.9 % NACKs.
- One second later the network handed over to band 8 (events below).

**Cell edge in the basement, band 8, a few seconds before the drop:**

```
SIM7600G-H;time=16:37:18;dl_tbs=52;dl_bler=8.0%;dl_harq_retx=2;dl_harq_retx_pct=3.8%;dl_resid=0;dl_mcs=2.3;dl_rbs=4.1;dl_mimo=4%;dl_rate=0.01Mbps;pdcch_agg=1.38;ul_tx=774;ul_harq_retx=85;ul_harq_retx_pct=11.0%;ul_nack=48;ul_nack_pct=7.2%;ul_rate=0.43Mbps;ul_grant=0.47Mbps;ul_grant_used=100%;ul_rbs=12.9;ul_mod=QPSK;ul_coderate=0.20;ul_pwr=40.9dBm;ul_txpwr=22.6dBm;ul_pwrlim=100.0%;ul_pc_corr=-5.0dB;pathloss=138.5dB;ul_buf=38.1KB;ul_buf_max=40.5KB;ul_buf_min=35.5KB;bsr=42.1KB;qdelay=609ms;qdelay_max=648ms;qdelay_min=569ms;qwarn=1;phr=-18dB;rlc_ul_retx=1;rlc_ul_nack=1;rlc_ul_tpoll=0;rlc_dl_retx=0;rlc_dl_nack=0;rlc_dl_drop=0;rlc_dl_treord=0;pdcp_ul_discard=66;cqi0=8.2;cqi1=NA;ri=1.0;temp=39C;vbat=3.98V;earfcn=3500;pci=186;rsrp0=-124.0dBm;rsrp1=-117.0dBm;rsrp_diff=-7.0dB;snr0=0.5dB;snr1=2.1dB;rsrq=-10.1dB;rssi=-89.7dBm;ncells=1;nb_earfcn=3500;nb_pci=187;nb_rsrp=-124.9dBm;nb_rsrq=-18.7dB;ho_margin=7.7dB;rlm_oos=0%;t310=0
```

- RSRP −124/−117 dBm, SNR 0.5/2.1 dB, path loss 138.5 dB, headroom −18 dB, power-limited 100 %.
- Only 0.43 of the 1 Mbit/s gets through: a standing queue of 35.5 KB (569 ms), `qwarn=1`.
- `pdcp_ul_discard=66`: the modem threw away uplink packets that waited too long. Rank 1 (`cqi1=NA`).

**Handover band 3 → band 8, same tower:**

```
SIM7600G-H;time=17:02:18.162;event=meas_report;rule=8:A2@?;srv_rsrp=-117dBm;srv_rsrq=-13.5dB;cells=none
SIM7600G-H;time=17:02:18.163;event=meas_config;rules=9:A2[serving<rsrp-118dBm,hys2dB,ttt40ms]@?,10:A1[serving>rsrp-114dBm,hys2dB,ttt640ms]@?,11:A5[serving<rsrp-115dBm&nb>rsrp-113dBm,hys1dB,ttt480ms]@1875,12:A5[serving<rsrp-115dBm&nb>rsrp-113dBm,hys1dB,ttt480ms]@3500,13:A5[serving<rsrp-115dBm&nb>rsrp-113dBm,hys1dB,ttt480ms]@6400;gaps=gp0:22;known=partial
SIM7600G-H;time=17:02:19.002;event=meas_report;rule=12:A5@3500;srv_rsrp=-116dBm;srv_rsrq=-13.5dB;cells=186:-93dBm:-7.5dB
SIM7600G-H;time=17:02:19.003;event=handover;from_pci=186;from_earfcn=1850;to_pci=186;to_earfcn=3500
SIM7600G-H;time=17:02:19.003;event=meas_config;rules=none;gaps=gp0:22;known=partial
SIM7600G-H;time=17:02:19.046;event=handover_done;pci=186;earfcn=3500;duration=24ms
SIM7600G-H;time=17:02:19.046;event=rach;reason=handover;result=success;contention=free;ta=15;distance=1172m
SIM7600G-H;time=17:02:19.085;event=meas_config;rules=1:A3[nb>serving+3dB,hys1dB,ttt320ms]@3500,2:A2[serving<rsrp-114dBm,hys2dB,ttt320ms]@3500;gaps=gp0:22;known=partial
SIM7600G-H;time=17:02:19;event=cell_change;earfcn_old=1850;pci_old=186;earfcn=3500;pci=186
```

The A2 report (band 3 below −116 dBm), the network's search rules with gaps on, the modem's A5 report for band 8
at −93 dBm, the handover command 1 ms later, completion after 24 ms, the random access (1172 m), new rules for
band 8, and `cell_change` from the next interval line.

**Band 20 → band 3 during a 4 Mbit/s upload** (24 Oct 2026, 22:30; `modem_link` at this commit, replayed from the
raw DIAG recording, times are the recording's). Nothing was weak here: the network moves the modem between bands
every few minutes with an A5 rule whose serving condition always holds (`serving<rsrp-44dBm`), i.e. load balancing:

```
SIM7600G-H;time=22:30:13;dl_tbs=38;dl_bler=0.0%;dl_harq_retx=0;dl_harq_retx_pct=0.0%;dl_resid=0;dl_mcs=2.3;dl_rbs=3.0;dl_mimo=12%;dl_rate=0.01Mbps;pdcch_agg=1.01;ul_tx=491;ul_harq_retx=6;ul_harq_retx_pct=1.2%;ul_nack=2;ul_nack_pct=0.4%;ul_rate=4.30Mbps;ul_grant=4.02Mbps;ul_grant_used=100%;ul_rbs=16.8;ul_mod=16QAM;ul_coderate=0.90;ul_pwr=22.6dBm;ul_txpwr=19.2dBm;ul_pwrlim=53.0%;ul_pc_corr=-0.9dB;pathloss=117.0dB;ul_buf=5.4KB;ul_buf_max=11.7KB;ul_buf_min=1.7KB;bsr=5.1KB;qdelay=10ms;qdelay_max=22ms;qdelay_min=3ms;qwarn=0;phr=4dB;rlc_ul_retx=0;rlc_ul_nack=0;rlc_ul_tpoll=0;rlc_dl_retx=0;rlc_dl_nack=0;rlc_dl_drop=0;rlc_dl_treord=0;pdcp_ul_discard=0;cqi0=8.2;cqi1=11.6;ri=2.0;temp=39C;vbat=4.10V;earfcn=6400;pci=186;rsrp0=-101.7dBm;rsrp1=-102.9dBm;rsrp_diff=1.3dB;snr0=13.2dB;snr1=11.1dB;rsrq=-6.1dB;rssi=-76.6dBm;ncells=1;nb_earfcn=6400;nb_pci=187;nb_rsrp=-110.8dBm;nb_rsrq=-14.5dB;ho_margin=9.2dB;trigger=A5@1850;trigger_gap=0.0dB;trigger_nb=NA;trigger_held=0ms;trigger_ttt=640ms;rlm_oos=0%;t310=0
SIM7600G-H;time=22:30:13.962;event=meas_config;rules=3:A5[serving<rsrp-44dBm&nb>rsrp-112dBm,hys0dB,ttt640ms]@1850;gaps=gp0:32;known=partial
SIM7600G-H;time=22:30:14.853;event=meas_report;rule=3:A5@1850;srv_rsrp=-101dBm;srv_rsrq=-7.5dB;cells=186:-109dBm:-6dB
SIM7600G-H;time=22:30:14.854;event=handover;from_pci=186;from_earfcn=6400;to_pci=186;to_earfcn=1850
SIM7600G-H;time=22:30:14.854;event=meas_config;rules=none;gaps=gp0:32;known=partial
SIM7600G-H;time=22:30:14.882;event=handover_done;pci=186;earfcn=1850;duration=28ms
SIM7600G-H;time=22:30:14.934;event=rach;reason=handover;result=success;contention=free;ta=17;distance=1328m
SIM7600G-H;time=22:30:14.934;event=meas_config;rules=1:A3[nb>serving+3dB,hys1dB,ttt320ms]@1850,2:A2[serving<rsrp-114dBm,hys2dB,ttt320ms]@1850;gaps=gp0:32;known=partial
SIM7600G-H;time=22:30:14;event=cell_change;earfcn_old=6400;pci_old=186;earfcn=1850;pci=186
```

- The line before: band 20, RSRP −101.7 dBm, 4.3 Mbit/s with a 1.7 KB standing queue (3 ms).
- 22:30:13.962 the network adds `3:A5[...]@1850` with gaps on; `trigger=A5@1850`, `trigger_gap=0.0dB` (the serving
  side always holds). `trigger_nb=NA` and `trigger_held=0ms`: the SIM7600 doesn't log its measurements on other
  bands (see [Known issues](#known-issues)), so the band 3 cell only shows up in the report.
- 0.89 s later (gap start + 640 ms) the report with band 3 at −109 dBm, the handover 1 ms after it, done in 28 ms.
- Band 3 is weaker (−109/−108 dBm, path loss 121 dB instead of 117) but 20 MHz wide.

**Band 3, 20 Mbit/s offered: about the uplink's limit** (two seconds after the upload stepped up to 20 Mbit/s):

```
SIM7600G-H;time=22:30:21;dl_tbs=36;dl_bler=0.0%;dl_harq_retx=0;dl_harq_retx_pct=0.0%;dl_resid=0;dl_mcs=0.5;dl_rbs=4.0;dl_mimo=0%;dl_rate=0.01Mbps;pdcch_agg=1.05;ul_tx=1014;ul_harq_retx=89;ul_harq_retx_pct=8.8%;ul_nack=67;ul_nack_pct=6.5%;ul_rate=20.90Mbps;ul_grant=20.35Mbps;ul_grant_used=100%;ul_rbs=77.4;ul_mod=16QAM;ul_coderate=0.52;ul_pwr=38.3dBm;ul_txpwr=21.8dBm;ul_pwrlim=100.0%;ul_pc_corr=1.0dB;pathloss=121.3dB;ul_buf=147.4KB;ul_buf_max=183.7KB;ul_buf_min=97.8KB;bsr=144.3KB;qdelay=56ms;qdelay_max=70ms;qdelay_min=37ms;qwarn=1;phr=-14dB;rlc_ul_retx=0;rlc_ul_nack=0;rlc_ul_tpoll=0;rlc_dl_retx=0;rlc_dl_nack=0;rlc_dl_drop=0;rlc_dl_treord=0;pdcp_ul_discard=0;cqi0=15.0;cqi1=13.2;ri=2.0;temp=39C;vbat=4.10V;earfcn=1850;pci=186;rsrp0=-109.6dBm;rsrp1=-108.4dBm;rsrp_diff=-1.2dB;snr0=12.5dB;snr1=15.1dB;rsrq=-11.5dB;rssi=-75.8dBm;ncells=2;nb_earfcn=1850;nb_pci=187;nb_rsrp=-125.1dBm;nb_rsrq=-26.1dB;ho_margin=16.8dB;trigger=A2;trigger_gap=7.6dB;trigger_nb=NA;trigger_held=0ms;trigger_ttt=320ms;rlm_oos=0%;t310=0
```

- 20.9 Mbit/s carried with 77 RBs at 16QAM, power-limited 100 % (requested 38.3 dBm, actual 21.8 dBm, headroom −14 dB).
- A standing queue of 97.8 KB (37 ms), `qwarn=1`; it shrank to 15–30 KB in the next seconds, so 20 Mbit/s was just
  about what this band carried here. `bsr=144.3KB` is near its 150 KB ceiling.

**Drop at the cell edge and reconnect:**

```
SIM7600G-H;time=16:37:14.787;event=meas_report;rule=2:?;srv_rsrp=-118dBm;srv_rsrq=-7dB;cells=none
SIM7600G-H;time=16:37:14.788;event=meas_config;rules=13:A2[serving<rsrp-118dBm,hys2dB,ttt40ms]@?,14:A1[serving>rsrp-114dBm,hys2dB,ttt640ms]@?,15:A5[serving<rsrp-115dBm&nb>rsrp-113dBm,hys1dB,ttt480ms]@1850,16:A5[serving<rsrp-115dBm&nb>rsrp-113dBm,hys1dB,ttt480ms]@1875,17:A5[serving<rsrp-115dBm&nb>rsrp-113dBm,hys1dB,ttt480ms]@6400;gaps=gp0:20;known=partial
SIM7600G-H;time=16:37:15.435;event=meas_report;rule=13:A2@?;srv_rsrp=-120dBm;srv_rsrq=-7.5dB;cells=none
SIM7600G-H;time=16:37:15.489;event=meas_config;rules=14:A1[serving>rsrp-114dBm,hys2dB,ttt640ms]@?,15:A5[serving<rsrp-115dBm&nb>rsrp-113dBm,hys1dB,ttt480ms]@1850,16:A5[serving<rsrp-115dBm&nb>rsrp-113dBm,hys1dB,ttt480ms]@1875,17:A5[serving<rsrp-115dBm&nb>rsrp-113dBm,hys1dB,ttt480ms]@6400,18:A2[serving<rsrp-123dBm,hys1dB,ttt320ms]@?;gaps=gp0:20;known=partial
SIM7600G-H;time=16:37:19.786;event=meas_config;rules=14:A1[serving>rsrp-114dBm,hys2dB,ttt640ms]@?,18:A2[serving<rsrp-123dBm,hys1dB,ttt320ms]@?;gaps=off;known=partial
SIM7600G-H;time=16:37:26.586;event=meas_report;rule=18:A2@?;srv_rsrp=-126dBm;srv_rsrq=-13dB;cells=none
SIM7600G-H;time=16:37:26.586;event=rrc_release;cause=other;connected=NA;pci=186;earfcn=3500
SIM7600G-H;time=16:38:05.463;event=rach;reason=connection;result=success;contention=based;ta=16;distance=1250m
SIM7600G-H;time=16:38:05.463;event=rrc_setup;cause=mo-Data;pci=186;earfcn=3500
SIM7600G-H;time=16:38:05.463;event=meas_config;rules=1:A3[nb>serving+3dB,hys1dB,ttt320ms]@3500,2:A2[serving<rsrp-114dBm,hys2dB,ttt320ms]@3500;gaps=off;known=full
```

The A2 reports, a 5 s search for band 3 / band 20 that finds nothing, the last-resort A2 at −123 dBm, the report
at −126 dBm, the release, 39 s without service, then random access and a new connection on the same cell.

**Summary of the basement walk (449 s):**

```
SIM7600G-H;event=summary;duration=449s;dl_total=0.6MB;dl_avg=0.01Mbps;dl_peak=0.37Mbps;dl_bler=1.2%;dl_harq_retx=265;dl_harq_retx_pct=1.5%;dl_resid=35;ul_total=47.2MB;ul_avg=0.84Mbps;ul_peak=12.01Mbps;ul_harq_retx=6211;ul_harq_retx_pct=4.8%;ul_nack=3368;ul_nack_pct=2.6%;ul_pwrlim=39.2%;ul_grant_used=84.7%;pathloss_min=101dB;pathloss_max=141dB;ul_buf_max=346.4KB;qdelay_max=888ms;qwarn_intervals=18;intervals=449;rlc_ul_retx=383;rlc_ul_nack=68;rlc_dl_retx=0;rlc_dl_nack=0;rlc_dl_drop=0;pdcp_ul_discard=682;t310_intervals=0;rrc_setups=1;rrc_releases=1;meas_reports=6;handovers=0;handovers_done=0;reestablishments=0;temp_min=36C;temp_max=47C;vbat_min=3.98V;vbat_max=4.16V
```

`ul_peak=12.01Mbps` and `ul_buf_max=346.4KB` are the backlog the modem sent right after reconnecting; the 682
discarded PDCP packets and path loss up to 141 dB are from the cell edge.

---

## Measured on this setup

| Situation | Values |
|---|---|
| Good signal, band 8 | RSRP −95 to −100 dBm, SNR 15–20 dB, path loss ~110 dB, `ul_txpwr` 10–15 dBm at 1 Mbit/s, `qdelay` ~10 ms. |
| Uplink capacity | About 9–13 Mbit/s on band 8 (10 MHz) at −100 dBm. About 20 Mbit/s on band 3 (20 MHz) at −109 dBm, power-limited, 77 RBs 16QAM. Above that a standing queue builds. |
| Fair signal | RSRP −105 to −110 dBm: transmit power ~21 dBm, `ul_pwrlim` 30–50 % at 1 Mbit/s, still working. |
| Cell edge | Below about −118 dBm: `ul_txpwr` 22–23 dBm, `ul_pwrlim` 100 %, path loss 135–140 dB. 1 Mbit/s got through at only ~0.7 Mbit/s, `qdelay` up to 650 ms, `pdcch_agg` rose to 4–8. |
| Release | The network released the connection at about −126 dBm after its last-resort A2 (−123 dBm, 320 ms). |
| Queue limits | `bsr` saturates at 150 KB. In the weak-signal phase the modem's buffer stopped growing at ~40 KB. After a 39 s outage it sent a 346 KB backlog on reconnect (pings 38 s old). Offered 20 Mbit/s on band 20 (16 Mbit/s carried) and band 8 at −108 dBm (8 Mbit/s carried), the buffer (0xB066, exact) swung between ~160 and 270–294 KB (mean ~215 KB) while `bsr` stayed at its 150 KB ceiling, and the modem dropped the rest silently: 38 % of the packets, with `pdcp_ul_discard=0` (they never reach PDCP). `ul_buf_min` / `qdelay_min` (82 ms, 160 ms) showed the overload correctly. |
| Handover | Band 3 → band 8 on the same tower: 24 ms, one ping 112 ms, none lost. Band 8 → band 20: 31 ms; band 20 → band 3 during a 4 Mbit/s upload: 28 ms, a 44 KB queue spike (85 ms) that drained within the second. |
| Network rules here | Normal: A3 (+3 dB, 320 ms) and A2 −114 dBm. Below −118 dBm: a 5 s search for band 3 (1850, 1875) and band 20 (6400) with gaps. Last resort: A2 −123 dBm, then release. Every few minutes, also with good signal: an A5 load-balancing check of one other band (`A5[serving<rsrp-44dBm&nb>rsrp-112dBm,hys0dB,ttt640ms]`, gaps on); a handover follows if that band is above −112 dBm. Seen on 24 Oct: 8 → 20, then 20 → 3 four minutes later. |

---

## Verified on this modem

On 24 Oct 2026 (22:14–22:40) a raw recording of the DIAG port was made while `modem_link` decoded it live, next to
values that don't come from DIAG: `AT+CPSI?`, `AT+CPMUTEMP` and `AT+CBC` every 3 s on the second AT port, and the
PC's byte counters of the modem's network interface every second. Load: idle, UDP upload at 0.5 / 1 / 2 / 4 /
20 Mbit/s, a 10 MB download. Two handovers happened during it (band 8 → 20 and 20 → 3).

| What | Compared with | Result |
|---|---|---|
| DIAG log versions (table above) | Raw recording | All as listed. 0xB195 carries subpackets 30 v3 and 31 v4. |
| `ul_rate` | Bytes the PC sent | 0.51 / 1.0 / 2.0 / 4.1 / 20.1 Mbit/s for 0.50 / 1.0 / 2.0 / 4.0 / 20 Mbit/s of IP packets. Total over the window 25.0 MB vs 26.1 MB (incl. 0.34 MB of Ethernet headers). Every fifth line was ~20 % high (AT poll timing), fixed since: see [Known issues](#known-issues). |
| `dl_rate`, `dl_total` | Bytes the PC received | Same shape per second, total 84.7 vs 83.1 Mbit; summary `dl_total=10.8MB` vs 10.5 MB. 64QAM (MCS 26), MIMO 99 %, `ri=2.0`, `cqi1` present while downloading. |
| `qdelay`, `qwarn` | `ul_buf` ÷ `ul_rate` | Consistent (e.g. 145.2 KB at 20.8 Mbit/s = 56 ms, `qwarn=1`). `bsr` tracks `ul_buf`. |
| `ul_pwr`, `ul_txpwr`, `ul_pwrlim`, `phr` | Each other | Actual power tops out at 22–23 dBm; `phr` ≈ 23 − requested (−15 dB at 38–39 dBm requested); `ul_pwrlim` high exactly when requested > 23 dBm. |
| `earfcn`, `pci` | `AT+CPSI?` | Always the same, including across the band 20 → 3 handover. |
| `rsrp0`/`rsrp1` | `AT+CPSI?` RSRP | CPSI shows the better antenna: −101.5 vs `rsrp0` −101.5 on band 20, −108.2 vs `rsrp1` −108.2 on band 3. |
| `rsrq`, `rssi` | `AT+CPSI?` | Within about 1 dB (2 dB for RSSI); CPSI is a snapshot, `modem_link` an average. |
| `snr0`/`snr1` | `AT+CPSI?` SINR | CPSI reads 3–5 dB higher (16–17 dB vs 10–15 dB). |
| `temp`, `vbat` | `AT+CPMUTEMP`, `AT+CBC` | Same. |
| Events | The RRC messages themselves, timing | `meas_config` rules, `meas_report` (A5 fired 640 ms after the gap started, as its `ttt`), `handover` + `handover_done` (28 / 31 ms), `rach` (`ta=17` = 1328 m), `rrc_setup` / `rrc_release` (`connected` 219.2 s vs 219.4 s by the PC clock), `cell_change`. |
| Summary line | Bytes, events | `ul_total`, `dl_total`, `ul_peak`, `handovers=1`, `meas_reports=1` match. |
| After the fixes, 20 min live (25 Oct, 08:22–08:42) | Same ground truth, 4 load cycles | 1225 lines in 1225 s, one per second. `ul_rate` 0.97–0.98 of the PC's IP rate at 1 and 4 Mbit/s on band 20 and band 8, ±10 % per line, no 5-s pattern; `dl_total` 13.7 vs 13.2 MB. Largest `ul_buf_max` 294 KB. `earfcn`/`pci` equal to CPSI in all 409 samples, RSRP within ±1 dB, temperature and voltage equal. A load-balancing handover band 20 → 8 (25 ms) with report, `rach`, `cell_change` consistent; summary counts equal the events. |
| 7b07d92 vs `modem/ep06` | Same recording replayed into both | Same events, same fields apart from the EP06 branch's `scc_*` / `dl_scc_rate` (NA here) and `trigger` naming A1/A2 with their frequency (`A2@1850` instead of `A2`). |

---

## Known issues

- **No neighbours on other bands.** The SIM7600 logs only the serving frequency's cells (0xB179, 0xB195), also
  while gaps are on. So `nb_*`, `ncells` and `ho_margin` only ever show cells on the serving band, and for an A5/A4
  rule on another band `trigger_nb=NA`, `trigger_gap` stays at 0.0 dB once the serving part holds and
  `trigger_held` stays 0 ms, right up to the handover. The cell the modem found there is only in the `meas_report`
  event. With the load-balancing A5 (`serving<rsrp-44dBm`) this means `trigger_gap=0.0dB` for the 1–2 s of each
  such check; `modem_alink` pauses raising for that time (`edge`).
- **Interface name** on the PC: see [Setup](#setup).
- **Trigger fields need the start of the connection.** If `modem_link` starts while the modem is already connected,
  `trigger=NA` until the network sends new rules.

**Fixed after the verification** (lines from older builds still show these):

- **Every fifth line overstated the counts by ~20 %.** Every 5 s `modem_link` asks the AT port for temperature and
  voltage, which blocks for about 0.2 s; the DIAG data that arrived meanwhile was counted in the next interval
  without that time (at a steady 1 Mbit/s `ul_rate` read 1.18–1.25 every 5 s, at `modem_link 0.25` about double).
  Now each interval starts where the previous one ended, so lines also keep an exact cadence (before, an interval
  lasted ~1.03 s and a second label was skipped about every 35 s).
- **One garbage queue sample of ~4 GB** (`ul_buf_max=4294966.7KB` on the basement walk): a buffer counter that
  briefly went negative during a band search, read as unsigned. Such samples are now dropped.

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
SIM7600G-H;time=17:03:44;dl_tbs=39;dl_bler=0.0%;...;rsrp0=-105.0dBm;rsrp1=-103.1dBm;...;t310=0
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
| `time` | Local time (HH:MM:SS, cut to the whole second) at the end of the interval; intervals follow each other without gaps, so at 1 s every second appears once. The interval is measured on the PC's clock as the DIAG data arrives (30 ms after the modem made it, 99 % within ~100 ms). |

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
| `dl_mimo` | % | Share of new-data subframes that carried 2 codewords (2×2 spatial multiplexing). | 0 % = rank 1 only (weak signal, or one antenna poor). |
| `dl_rate` | Mbps | Downlink goodput at the physical layer: bytes of TBs that passed CRC. | Includes RLC/PDCP/IP headers, so a few % above what an application sees. |
| `pdcch_agg` | | Mean PDCCH aggregation level (1, 2, 4 or 8) of the scheduling messages. Source: PHICH log (0xB16B). | 1 = good. The network raises it to protect the control channel when the radio is poor; 4–8 right before a drop was seen on the basement walk. |

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
| `ul_grant_used` | % | | Share of granted bytes filled with data (the rest is padding). | Here the network sizes grants to the modem's buffer reports, so it reads ~100 % with any steady stream above ~2 Mbit/s even without a queue. Only together with `qdelay_min` > 0 does it mean the grant is the bottleneck. |
| `ul_rbs` | | PUSCH tx | Mean resource blocks per uplink transmission. | |
| `ul_mod` | | PUSCH tx | Most used uplink modulation in the interval: `QPSK`, `16QAM`, `64QAM`. | The SIM7600 tops out at 16QAM. |
| `ul_coderate` | | PUSCH tx | Mean coding rate as the modem logs it (about 0–1; a value just above 1 shows up now and then with retransmissions). | Higher = more data per resource block. |

### Uplink power

| Field | Unit | Source | Meaning | How to read it |
|---|---|---|---|---|
| `ul_pwr` | dBm | PUSCH tx | Mean **requested** PUSCH power: what power control asks for. | Can exceed 23 dBm. |
| `ul_txpwr` | dBm | PUSCH power control (0xB16E) | Mean **actual** transmit power. | The SIM7600's maximum is 23 dBm. The modem logs 0xB16E in batches about 1.5 times a second, so at 1 s intervals some lines have `NA` here and in `pathloss` / `ul_pc_corr`. |
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

These all stay 0 on a clean link. HARQ (fast, per transmission) catches nearly everything; RLC is the slower second line.

### Channel quality reports

Source: PUCCH CSI reports (0xB14D), what the modem tells the tower about the downlink.

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

Source: serving cell measurement (0xB193), about 50 samples a second, averaged.

| Field | Unit | Meaning | How to read it |
|---|---|---|---|
| `earfcn` | | Downlink channel number of the serving cell. It gives the band: 1200–1949 = band 3 (1800 MHz), 3450–3799 = band 8 (900 MHz), 6150–6449 = band 20 (800 MHz). | Here: 1850 = band 3, 3500 = band 8, 6400 = band 20. |
| `pci` | | Physical cell ID (0–503) of the serving cell. | Same tower, different band = usually the same PCI (186 here). Neighbouring PCIs (187) are often other sectors. |
| `rsrp0` | dBm | Reference signal received power on RX antenna 0. | > −90 excellent, −90 to −105 good, −105 to −115 fair, −115 to −120 poor, < −120 cell edge. |
| `rsrp1` | dBm | Same on RX antenna 1 (diversity). | `AT+CPSI?` shows the better of `rsrp0`/`rsrp1`. |
| `rsrp_diff` | dB | `rsrp0 − rsrp1`. | More than ~6–10 dB = an antenna or cable problem, or a strongly orientation-dependent setup. |
| `snr0`, `snr1` | dB | Signal-to-noise per antenna (approximate). | Above ~15 dB good, below 0 the link is about to fail. `AT+CPSI?`'s SINR reads 3–5 dB higher. |
| `rsrq` | dB | Reference signal received quality, combined. | > −10 good, −10 to −15 fair, < −15 poor (interference or a loaded cell). |
| `rssi` | dBm | Total received power, both antennas, including interference and other users' traffic. | |

### Neighbour cells

Source: intra-frequency (0xB179) and connected-mode (0xB195) neighbour measurements. On the SIM7600 both contain
only cells on the serving band, also during a search: the cells the modem measures on other bands (in the gaps)
are not logged; they appear only in `meas_report` (see [Known issues](#known-issues)).

| Field | Unit | Meaning | How to read it |
|---|---|---|---|
| `ncells` | count | Neighbour cells measured in the interval. | |
| `nb_earfcn` | | Channel of the strongest neighbour. | |
| `nb_pci` | | Its physical cell ID. | |
| `nb_rsrp` | dBm | Its RSRP. | |
| `nb_rsrq` | dB | Its RSRQ. | |
| `ho_margin` | dB | Serving RSRP − strongest neighbour RSRP. | Small or negative = a stronger cell exists. Whether a handover happens is the network's decision, by its own rules: see the trigger fields. |

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
SIM7600G-H;time=17:02:19.003;event=handover;from_pci=186;from_earfcn=1850;to_pci=186;to_earfcn=3500
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
**drop**: the modem then has no service until it finds a cell again (39 s on the basement walk).

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
- **Edge:** the `trigger` is within 2 dB of firing (search, handover or release; not A1): no raising.
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

**Output.** Every change is printed and sent to `GROUND_IP:2224`. Example from the basement walk replayed into
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

DIAG log packets `modem_link` subscribes to (SIM7600 / EC25 versions):

| Code | Name | Gives |
|---|---|---|
| 0xB173 | PDSCH statistics v5 | Downlink TBs, BLER, HARQ, MCS, RBs, MIMO, `dl_rate` |
| 0xB139 | PUSCH Tx report v25 | Uplink transmissions, RBs, modulation, coding rate, requested power |
| 0xB064 | MAC UL transport block | `ul_rate`, BSR, PHR |
| 0xB066 | MAC UL buffer status v5 | `ul_buf` (exact queue, every millisecond) |
| 0xB067 | MAC UL Tx statistics | `ul_grant`, `ul_grant_used` |
| 0xB16B | PDCCH/PHICH v5 | `ul_nack`, `pdcch_agg` |
| 0xB16E | PUSCH power control v5 | `ul_txpwr`, `pathloss`, `ul_pc_corr` |
| 0xB14D | PUCCH CSI report v24 | `cqi0`, `cqi1`, `ri` |
| 0xB193 | Serving cell measurement v18 | `earfcn`, `pci`, RSRP/SNR per antenna, RSRQ, RSSI |
| 0xB179 | Intra-frequency neighbour measurement v4 | Neighbours, filtered serving RSRP (trigger) |
| 0xB195 | Connected-mode neighbour measurement | Neighbours on every measured frequency |
| 0xB18A | Radio link monitoring v1 | `rlm_oos`, `t310` |
| 0xB087, 0xB097, 0xB0B4 | RLC DL, RLC UL, PDCP UL statistics | RLC/PDCP counters |
| 0xB0C0 | RRC OTA message | All events except `cell_change` and `rach` |
| 0xB061, 0xB062 | RACH trigger / attempt | `rach` events |

---

---

## Other modems

- [README_EC25.md](README_EC25.md): Quectel EC25, same chipset family, same output.
- [README_EP06.md](README_EP06.md): Quectel EP06, carrier aggregation, needs the `modem/ep06` branch.
