/* Live LTE link-quality monitor for SIM7600 / Quectel EC25 (Qualcomm MDM9x07) over DIAG (/dev/ttyUSB0).
 *
 * Per interval prints:
 *   DL  (0xB173 PDSCH stat v5): scheduled TBs, first-tx BLER, HARQ retx, residual HARQ failures
 *       (TB abandoned -> RLC must recover), MCS, RBs, share of subframes with 2 codewords
 *       (2x2 MIMO spatial multiplexing), PHY goodput
 *   UL  (0xB139 PUSCH tx v25 + 0xB064 MAC UL TB): PUSCH transmissions, HARQ retx, MAC goodput,
 *       RBs, modulation, coding rate, requested PUSCH power (>23 dBm = power limited)
 *   UL queue (MAC control elements in 0xB064): BSR = bytes waiting in the modem's uplink buffer, queue delay =
 *       BSR / uplink rate (mean and max, ms; '!' at >= 50 ms: queue building, UDP loss followed 1-2 s later in
 *       tests), PHR = power headroom dB (negative = at max transmit power)
 *   CSI (0xB14D PUCCH CSI v24): wideband CQI per codeword and rank indicator (RI)
 *   RF  (0xB193 serving cell meas v18): EARFCN, PCI, RSRP per RX antenna and their difference, SNR per RX
 *       (approximate), combined RSRQ and RSSI; all averaged over the interval
 *   UL grant / power / HARQ (0xB067 MAC UL Tx stats, 0xB16E PUSCH power control v5, 0xB16B PHICH v5): Mbit/s granted
 *       by the eNB and share used, PHICH NACKs (direct UL HARQ failures), actual tx power, DL path loss, closed-loop
 *       power correction f(i), mean PDCCH aggregation level (1 good .. 8 = eNB protecting control in poor radio)
 *   UL buffer (0xB066 MAC UL buffer status v5): exact bytes queued in the modem every subframe (BSR tops out at
 *       150 KB); queue delay uses it when logged.
 *       ul_buf_min / qdelay_min: smallest queue of the interval = standing queue (keyframe spikes do not raise it)
 *   RLC / PDCP (0xB087, 0xB097, 0xB0B4 statistics): retransmissions, NACKs, dropped PDUs, t-Reordering expiries,
 *       PDCP discards, increase over the interval (NA = no statistics packet in the interval, they come every ~1.3 s)
 *   Neighbours (0xB179 v4 intra-frequency, 0xB195 every measured frequency): count, strongest EARFCN/PCI/RSRP/RSRQ,
 *       handover margin = serving - best neighbour RSRP
 *   Mobility events, printed when they happen (RRC 0xB0C0 via lte_rrc.h, RACH 0xB061/0xB062): rrc_setup / rrc_release,
 *       meas_config (the network's handover rules: measured EARFCNs, A1-A5/B1-B2 thresholds, time to trigger, gaps),
 *       meas_report (modem reports a neighbour meeting a rule, usually just before a handover), handover /
 *       handover_done (target, duration), rach (timing advance -> distance to the tower), reestablishment (radio
 *       link failure)
 *   RLM (0xB18A v1): out-of-sync BLER estimate and T310 (radio link failure timer running)
 *   Modem temperature / supply voltage via AT (SIMCom AT+CPMUTEMP, Quectel AT+QTEMP; AT+CBC) every 5 s; NA if the
 *   AT port is busy.
 *
 * Output: one line per interval, "<model>;name=value<unit>;...", fields always in the same order, NA = no data.
 *   Event lines: ...;event=cell_change;..., the mobility events above, and on exit ...;event=summary;...
 *   --table prints the old column view.
 *   The key=value lines are also sent over UDP to GROUND_IP from /etc/masina.conf, port 2224 (same as the SSC
 *   telemetry from masinatelemetry; the ground tells them apart by the first field). With DEBUG=2 in masina.conf
 *   they are also appended to /mnt/mmcblk0p1/modem_link_<date>_<time>.log if the SD card is mounted rw.
 *   A copy goes to 127.0.0.1:2225 for modem_alink (adaptive video bitrate); nothing happens if it isn't running.
 *
 * usage: modem_link [interval_s] [diag_port] [at_port] [--table]      Ctrl-C prints totals and exits
 */
#include <mntent.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include "lte_common.h"
#include "lte_rrc.h"

static volatile sig_atomic_t stop;
static void on_sig(int s) { (void)s; stop = 1; }

static const char *HEADER =
    "         |---------------------------- downlink ----------------------------|"
    "--------------------------- uplink ----------------------------|----------- UL grant / power -----------|"
    "------ UL queue -------|  CSI          | modem   |\n"
    "time     |   TBs  BLER1st HARQretx    resid  MCS   RBs  MIMO%  Mbit |"
    "    tx HARQretx       Mbit   RBs   mod  rate  pwr  pwr>23 |  NACK%  grant Mbit used%  txpwr  PL  f(i) |"
    " buf KB qdly ms qmax PHR | CQI0/1    RI  | degC  V  | EARFCN PCI  RSRP0/1 dBm  diff   SNR0/1 dB    RSRQ  RSSI | nbPCI  RSRP  margin";

/* modem temperature and supply voltage over AT, polled every HEALTH_PERIOD s */
#define HEALTH_PERIOD 5
typedef struct {
    int fd;
    double last;
    int have_t, have_v;
    int temp, tmin, tmax;
    double volt, vmin, vmax;
    char model[64];
    int quectel;
} health_t;

static void health_open(health_t *h, const char *port, diag_t *d)
{
    const char *c[] = { port, "/dev/ttyUSB2", "/dev/ttyUSB3" };
    h->fd = -1;
    h->last = -1e9;
    for (int i = port ? 0 : 1; i < 3 && h->fd < 0; i++)
        h->fd = tty_open(c[i]);
    /* model from AT+CGMM (SIMCOM_SIM7600G-H -> SIM7600G-H, EC25), else from the DIAG build id */
    char v[128];
    h->model[0] = 0;
    if (at_val(h->fd, "AT+CGMM", NULL, v, sizeof(v))) {
        const char *m = strncmp(v, "SIMCOM_", 7) ? v : v + 7;
        if (*m && !strchr(m, ' ') && !strchr(m, ':')) snprintf(h->model, sizeof(h->model), "%s", m);
    }
    if (!h->model[0] && !diag_model(d, h->model, sizeof(h->model)))
        snprintf(h->model, sizeof(h->model), "LTE");
    h->quectel = is_quectel(h->model);
}

/* ---- key=value output: "MODEL;name=value<unit>;..." */
static char line[4096];
static size_t ll;

static void kv_start(const char *model) { ll = snprintf(line, sizeof(line), "%s", model); }

static void kv_s(const char *k, const char *v)
{
    if (ll < sizeof(line)) ll += snprintf(line + ll, sizeof(line) - ll, ";%s=%s", k, v);
}

static void kv_l(const char *k, long v)
{
    char b[32];
    snprintf(b, sizeof(b), "%ld", v);
    kv_s(k, b);
}

/* number with unit, or NA when !ok */
static void kv_f(const char *k, int ok, double v, int prec, const char *unit)
{
    char b[48];
    if (ok) snprintf(b, sizeof(b), "%.*f%s", prec, v, unit);
    else snprintf(b, sizeof(b), "NA");
    kv_s(k, b);
}

/* ---- outputs besides stdout, configured from /etc/masina.conf like the other masina binaries:
 *      UDP copy to GROUND_IP:2224 and, with DEBUG=2, a log file on the SD card */
#define MASINA_CONF "/etc/masina.conf"
#define GROUND_PORT "2224"
#define LOG_DIR "/mnt/mmcblk0p1"
#define ALINK_PORT 2225 /* modem_alink listens here on 127.0.0.1 */

typedef struct {
    char ground_ip[128];
    int debug; /* 0 off, 1 console, 2+ file; only the file mode matters here */
} masina_conf_t;

static int udp_fd = -1, log_fd = -1, alink_fd = -1;
static struct sockaddr_storage udp_addr;
static socklen_t udp_addrlen;
static struct sockaddr_in alink_addr;

/* the last occurrence of a key wins, as in Config::readConfig */
static int conf_read(masina_conf_t *c)
{
    FILE *f = fopen(MASINA_CONF, "r");
    if (!f) {
        fprintf(stderr, "warning: %s not found, UDP output disabled\n", MASINA_CONF);
        return 0;
    }
    char buf[256];
    while (fgets(buf, sizeof(buf), f)) {
        sscanf(buf, "GROUND_IP=%127s", c->ground_ip);
        sscanf(buf, "DEBUG=%d", &c->debug);
    }
    fclose(f);
    return 1;
}

/* GROUND_IP may be an IP or a hostname; without it the lines only go to stdout */
static void udp_open(const char *host)
{
    if (!*host) {
        fprintf(stderr, "warning: no GROUND_IP in %s, UDP output disabled\n", MASINA_CONF);
        return;
    }
    struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_DGRAM }, *res;
    if (getaddrinfo(host, GROUND_PORT, &hints, &res) != 0) {
        fprintf(stderr, "warning: cannot resolve GROUND_IP %s, UDP output disabled\n", host);
        return;
    }
    /* non-blocking: a dead link must never stall the DIAG loop */
    udp_fd = socket(res->ai_family, res->ai_socktype | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    memcpy(&udp_addr, res->ai_addr, res->ai_addrlen);
    udp_addrlen = res->ai_addrlen;
    freeaddrinfo(res);
}

/* local copy for modem_alink; sends to a port nobody listens on are dropped by the kernel */
static void alink_open(void)
{
    alink_addr.sin_family = AF_INET;
    alink_addr.sin_port = htons(ALINK_PORT);
    alink_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    alink_fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
}

/* true if LOG_DIR is a mount point mounted read-write (same check as Log() in utils.cpp) */
static int log_dir_writable(void)
{
    FILE *mounts = setmntent("/proc/mounts", "r");
    if (!mounts)
        return 0;
    int writable = 0;
    struct mntent *m;
    while ((m = getmntent(mounts)) != NULL)
        if (!strcmp(m->mnt_dir, LOG_DIR))
            writable = hasmntopt(m, "rw") != NULL; /* last match wins (remounts stack) */
    endmntent(mounts);
    return writable && access(LOG_DIR, W_OK) == 0;
}

/* LOG_DIR/modem_link_<date>_<time>.log, a new file per start; never truncated or rotated */
static void log_open(void)
{
    if (!log_dir_writable()) {
        fprintf(stderr, "Log file disabled: " LOG_DIR " not mounted rw\n");
        return;
    }
    time_t t = time(NULL);
    struct tm tm;
    localtime_r(&t, &tm);
    char stamp[32], path[96];
    strftime(stamp, sizeof(stamp), "%Y%m%d_%H%M%S", &tm);
    snprintf(path, sizeof(path), LOG_DIR "/modem_link_%s.log", stamp);
    log_fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
    if (log_fd < 0)
        perror(path);
    else
        fprintf(stderr, "Logging to %s\n", path);
}

static void kv_end(void)
{
    puts(line);
    fflush(stdout);
    /* newline-terminated like the SSC lines: one datagram and one write per line */
    struct iovec iov[2] = { { line, strlen(line) }, { "\n", 1 } };
    if (udp_fd >= 0) {
        struct msghdr msg = { .msg_name = &udp_addr, .msg_namelen = udp_addrlen, .msg_iov = iov, .msg_iovlen = 2 };
        sendmsg(udp_fd, &msg, 0);
    }
    if (alink_fd >= 0) {
        struct msghdr msg = { .msg_name = &alink_addr, .msg_namelen = sizeof(alink_addr), .msg_iov = iov, .msg_iovlen = 2 };
        sendmsg(alink_fd, &msg, 0);
    }
    if (log_fd >= 0 && writev(log_fd, iov, 2) < 0) {
        /* card removed or full: stop logging instead of failing on every line */
        perror("log write");
        close(log_fd);
        log_fd = -1;
    }
}

static void health_poll(health_t *h)
{
    if (h->fd < 0 || now() - h->last < HEALTH_PERIOD)
        return;
    h->last = now();
    char v[128];
    int ht = (h->quectel ? at_val(h->fd, "AT+QTEMP", "+QTEMP", v, sizeof(v))
                         : at_val(h->fd, "AT+CPMUTEMP", "+CPMUTEMP", v, sizeof(v))) != NULL && parse_temp(v) > -1000;
    if (ht) {
        h->temp = parse_temp(v);
        if (!h->have_t || h->temp < h->tmin) h->tmin = h->temp;
        if (!h->have_t || h->temp > h->tmax) h->tmax = h->temp;
        h->have_t = 1;
    }
    int hv = at_val(h->fd, "AT+CBC", "+CBC", v, sizeof(v)) != NULL && parse_volt(v) > 0;
    if (hv) {
        h->volt = parse_volt(v);
        if (!h->have_v || h->volt < h->vmin) h->vmin = h->volt;
        if (!h->have_v || h->volt > h->vmax) h->vmax = h->volt;
        h->have_v = 1;
    }
    if (!ht) h->have_t = 0;
    if (!hv) h->have_v = 0;
}

static char *pct(char *o, double a, double b)
{
    if (b > 0) sprintf(o, "%5.1f%%", 100 * a / b);
    else sprintf(o, "    - ");
    return o;
}

static char *trim_pct(char *o)
{
    while (*o == ' ') o++;
    return o;
}

static char *avg(char *o, const acc_t *a, int w)
{
    if (a->n) sprintf(o, "%*.1f", w, mean(a));
    else sprintf(o, "%*s", w, "-");
    return o;
}

/* mobility events right away; time from the modem clock (+ offset to the host clock) with ms */
static void print_events(mobility_t *m, const char *model, int table, double toff)
{
    for (int i = 0; i < m->nev; i++) {
        double wt = wall_time();  /* host receive time; modem clock only for durations (see lte_link.py) */
        (void)toff;
        time_t w = (time_t)wt;
        char ts[32];
        strftime(ts, sizeof(ts), "%H:%M:%S", localtime(&w));
        snprintf(ts + 8, sizeof(ts) - 8, ".%03d", (int)((wt - (double)w) * 1000));
        if (!table) {
            ll = snprintf(line, sizeof(line), "%s;time=%s;%s", model, ts, m->ev[i].kv);
            kv_end();
            continue;
        }
        /* "event=x;k=v;k=v" -> "x k=v k=v" */
        const char *kv = m->ev[i].kv + 6;
        size_t n = strcspn(kv, ";");
        printf("*** %s %.*s", ts, (int)n, kv);
        for (const char *p = kv + n; *p; p++) putchar(*p == ';' ? ' ' : *p);
        putchar('\n');
    }
    m->nev = 0;
    fflush(stdout);
}

int main(int argc, char **argv)
{
    int table = 0, na = 0;
    const char *args[3] = { NULL, NULL, NULL };
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--table")) table = 1;
        else if (na < 3) args[na++] = argv[i];
    }
    double interval = args[0] ? atof(args[0]) : 1.0;
    const char *port = args[1] ? args[1] : "/dev/ttyUSB0";
    if (interval <= 0) {
        fprintf(stderr, "usage: %s [interval_s] [diag_port] [at_port] [--table]\n", argv[0]);
        return 2;
    }
    static diag_t d;
    if (diag_open(&d, port) < 0) {
        perror(port);
        return 1;
    }
    struct sigaction sa = { .sa_handler = on_sig };  /* no SA_RESTART: select() returns EINTR */
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    int codes[] = { LOG_PDSCH & 0xfff, LOG_PUSCH & 0xfff, LOG_MAC_UL & 0xfff, LOG_CSI & 0xfff, LOG_MEAS & 0xfff,
                    LOG_UL_BUF & 0xfff, LOG_UL_TXST & 0xfff, LOG_PHICH & 0xfff, LOG_PUSCH_PC & 0xfff, LOG_RLC_DL & 0xfff,
                    LOG_RLC_UL & 0xfff, LOG_PDCP_UL & 0xfff, LOG_NCELL & 0xfff, LOG_RLM & 0xfff, LOG_CONN_NB & 0xfff,
                    LOG_RRC_OTA & 0xfff, LOG_RACH_TRIG & 0xfff, LOG_RACH_ATT & 0xfff };
    int ok = -1;
    for (int i = 0; i < 3 && ok < 0; i++)
        ok = diag_set_log_mask(&d, 0xB, codes, sizeof(codes) / sizeof(codes[0]));
    if (ok < 0)
        fprintf(stderr, "warning: no response to log mask command on %s (is it the DIAG port?)\n", port);

    static health_t hl;
    health_open(&hl, args[2], &d);
    static masina_conf_t conf;
    if (!table)
        alink_open();
    if (!table && conf_read(&conf)) {
        udp_open(conf.ground_ip);
        if (conf.debug >= 2)
            log_open();
    }
    int seen_t = 0, seen_v = 0, tmin = 0, tmax = 0;
    double vmin = 0, vmax = 0;

    static stats_t s;
    static mobility_t mob;
    double toff = 0;
    int have_toff = 0;
    double tot_t = 0, peak_dl = 0, peak_ul = 0;
    long long tot_dl_bytes = 0, tot_ul_bytes = 0;
    long tot_dltb = 0, tot_first = 0, tot_fail = 0, tot_retx = 0, tot_resid = 0, tot_ultx = 0, tot_ulretx = 0, tot_pwrlim = 0, tot_qwarn = 0;
    double tot_qmax = 0, tot_bufmax = 0, pl_min = 0, pl_max = 0;
    long long tot_grx = 0, tot_gused = 0;
    long tot_ack = 0, tot_nack = 0, tot_l2[L2_N] = { 0 }, tot_t310 = 0;
    int have_pl = 0;
    int have_cell = 0, cell_e = 0, cell_p = 0;
    char b1[32], b2[32], b3[32], b4[32], b5[32], b6[32], b7[32], b8[32], b9[32], b10[32], b11[32], b12[32];

    long n_int = 0;
    for (long n = 0; !stop; n++, n_int++) {
        double t0 = now(), end = t0 + interval;
        int code, len;
        const uint8_t *body;
        while (!stop && (len = diag_log(&d, end, &code, &body)) != -2) {
            if (len < 0) continue;
            double mts = diag_log_time(body), off = now() - mts;
            if (!have_toff || off < toff) { toff = off; have_toff = 1; }
            if (stats_dispatch(&s, code, body, len)) continue;
            if (code == LOG_RRC_OTA) mob_rrc(&mob, mts, body, len);
            else if (code == LOG_RACH_TRIG) mob_rach_trig(&mob, body, len);
            else if (code == LOG_RACH_ATT) mob_rach_att(&mob, mts, body, len);
            if (mob.nev) print_events(&mob, hl.model, table, toff);
        }
        double el = now() - t0;
        if (el <= 0) el = 1e-3;
        health_poll(&hl);
        char tv[32];
        snprintf(tv, sizeof(tv), hl.have_t ? "%3d " : "  - ", hl.temp);
        snprintf(tv + 4, sizeof(tv) - 4, hl.have_v ? "%4.2f" : "  - ", hl.volt);
        if (hl.have_t) { if (!seen_t || hl.tmin < tmin) tmin = hl.tmin; if (!seen_t || hl.tmax > tmax) tmax = hl.tmax; seen_t = 1; }
        if (hl.have_v) { if (!seen_v || hl.vmin < vmin) vmin = hl.vmin; if (!seen_v || hl.vmax > vmax) vmax = hl.vmax; seen_v = 1; }
        char tm[16];
        time_t wall = time(NULL);
        strftime(tm, sizeof(tm), "%H:%M:%S", localtime(&wall));
        if (table && n % 20 == 0) puts(HEADER);
        if (s.rf_valid && have_cell && ((int)s.earfcn != cell_e || s.pci != cell_p)) {
            if (table)
                printf("*** cell change: EARFCN/PCI %d/%d -> %u/%d\n", cell_e, cell_p, s.earfcn, s.pci);
            else {
                kv_start(hl.model);
                kv_s("time", tm);
                kv_s("event", "cell_change");
                kv_l("earfcn_old", cell_e);
                kv_l("pci_old", cell_p);
                kv_l("earfcn", (long)s.earfcn);
                kv_l("pci", s.pci);
                kv_end();
            }
        }
        if (s.rf_valid) { have_cell = 1; cell_e = s.earfcn; cell_p = s.pci; }

        long ulr = stats_ul_retx(&s);
        int m = 0;
        for (int k = 1; k < 4; k++) if (s.ul_mod[k] > s.ul_mod[m]) m = k;
        char rf[128] = "-";
        if (s.rf_valid)
            snprintf(rf, sizeof(rf), "%6u %3d  %6.1f/%6.1f %+5.1f  %5.1f/%5.1f  %6.1f %5.1f", s.earfcn, s.pci, s.rsrp0, s.rsrp1,
                     s.rsrp0 - s.rsrp1, s.snr0, s.snr1, s.rsrq, s.rssi);
        double dlm = s.dl_ok_bytes * 8 / el / 1e6, ulm = s.ul_bytes * 8 / el / 1e6;
        char b13[32], qs[64];
        double qd = 0, qm = 0;
        int hq = stats_qdelay(&s, el, &qd, &qm);
        int n0 = hq ? snprintf(qs, sizeof(qs), "%6.1f %6.0f%c %4.0f ", mean(stats_queue(&s)) / 1000, qd,
                               stats_queue_warn(&s, el) ? '!' : ' ', qm)
                    : snprintf(qs, sizeof(qs), "     -      -     -  ");
        snprintf(qs + n0, sizeof(qs) - n0, s.phr.n ? "%3.0f" : "  -", mean(&s.phr));
        if (hq) { if (qm > tot_qmax) tot_qmax = qm; tot_qwarn += stats_queue_warn(&s, el); }
        long nph = s.ul_ack + s.ul_nack;
        int bn = stats_best_nb(&s);
        /* serving RSRP: 0xB179's filtered value, else the better antenna of 0xB193 */
        int hm = bn >= 0 && (s.nb_srv.n > 0 || s.rf_valid);
        double srv = s.nb_srv.n ? mean(&s.nb_srv) : s.rsrp0 > s.rsrp1 ? s.rsrp0 : s.rsrp1;
        double margin = hm ? srv - mean(&s.nb[bn].rsrp) : 0;
        if (!table) {
            long ntb = s.ntb[1] + s.ntb[2], nri = s.ri[1] + s.ri[2];
            kv_start(hl.model);
            kv_s("time", tm);
            kv_l("dl_tbs", s.dl_tb);
            kv_f("dl_bler", s.dl_first > 0, 100.0 * s.dl_first_fail / (s.dl_first ? s.dl_first : 1), 1, "%");
            kv_l("dl_harq_retx", s.dl_retx);
            kv_f("dl_harq_retx_pct", s.dl_tb > 0, 100.0 * s.dl_retx / (s.dl_tb ? s.dl_tb : 1), 1, "%");
            kv_l("dl_resid", s.dl_resid);
            kv_f("dl_mcs", s.mcs.n > 0, mean(&s.mcs), 1, "");
            kv_f("dl_rbs", s.rbs.n > 0, mean(&s.rbs), 1, "");
            kv_f("dl_mimo", ntb > 0, 100.0 * s.ntb[2] / (ntb ? ntb : 1), 0, "%");
            kv_f("dl_rate", 1, dlm, 2, "Mbps");
            kv_f("pdcch_agg", s.pdcch_agg.n > 0, mean(&s.pdcch_agg), 2, "");
            kv_l("ul_tx", (long)s.ul_n);
            kv_l("ul_harq_retx", ulr);
            kv_f("ul_harq_retx_pct", s.ul_n > 0, 100.0 * ulr / (s.ul_n ? s.ul_n : 1), 1, "%");
            kv_l("ul_nack", s.ul_nack);
            kv_f("ul_nack_pct", nph > 0, 100.0 * s.ul_nack / (nph ? nph : 1), 1, "%");
            kv_f("ul_rate", 1, ulm, 2, "Mbps");
            kv_f("ul_grant", 1, s.grant_rx * 8 / el / 1e6, 2, "Mbps");
            kv_f("ul_grant_used", s.grant_rx > 0, 100.0 * s.grant_used / (s.grant_rx ? s.grant_rx : 1), 0, "%");
            kv_f("ul_rbs", s.ul_rb.n > 0, mean(&s.ul_rb), 1, "");
            kv_s("ul_mod", s.ul_n && m ? MODS[m] : "NA");
            kv_f("ul_coderate", s.ul_rate.n > 0, mean(&s.ul_rate), 2, "");
            kv_f("ul_pwr", s.ul_pwr.n > 0, mean(&s.ul_pwr), 1, "dBm");
            kv_f("ul_txpwr", s.ul_txpwr.n > 0, mean(&s.ul_txpwr), 1, "dBm");
            kv_f("ul_pwrlim", s.ul_n > 0, 100.0 * s.ul_pwrlim / (s.ul_n ? s.ul_n : 1), 1, "%");
            kv_f("ul_pc_corr", s.pc_corr.n > 0, mean(&s.pc_corr), 1, "dB");
            kv_f("pathloss", s.pathloss.n > 0, mean(&s.pathloss), 1, "dB");
            kv_f("ul_buf", s.ul_buf.n > 0, mean(&s.ul_buf) / 1000, 1, "KB");
            kv_f("ul_buf_max", s.ul_buf.n > 0, s.ul_buf.max / 1000, 1, "KB");
            kv_f("ul_buf_min", s.ul_buf.n > 0, s.ul_buf.min / 1000, 1, "KB");
            kv_f("bsr", s.bsr.n > 0, mean(&s.bsr) / 1000, 1, "KB");
            kv_f("qdelay", hq, qd, 0, "ms");
            kv_f("qdelay_max", hq, qm, 0, "ms");
            double qmin = stats_qdelay_min(&s, el);
            kv_f("qdelay_min", qmin >= 0, qmin, 0, "ms");
            kv_l("qwarn", stats_queue_warn(&s, el));
            kv_f("phr", s.phr.n > 0, mean(&s.phr), 0, "dB");
            for (int k = 0; k < L2_N; k++)
                kv_f(L2_NAME[k], s.l2_valid, s.l2[k], 0, "");
            kv_f("cqi0", s.cqi.n > 0, mean(&s.cqi), 1, "");
            kv_f("cqi1", s.cqi1.n > 0, mean(&s.cqi1), 1, "");
            kv_f("ri", nri > 0, (s.ri[1] + 2.0 * s.ri[2]) / (nri ? nri : 1), 1, "");
            kv_f("temp", hl.have_t, hl.temp, 0, "C");
            kv_f("vbat", hl.have_v, hl.volt, 2, "V");
            kv_f("earfcn", s.rf_valid, s.earfcn, 0, "");
            kv_f("pci", s.rf_valid, s.pci, 0, "");
            kv_f("rsrp0", s.rf_valid, s.rsrp0, 1, "dBm");
            kv_f("rsrp1", s.rf_valid, s.rsrp1, 1, "dBm");
            kv_f("rsrp_diff", s.rf_valid, s.rsrp0 - s.rsrp1, 1, "dB");
            kv_f("snr0", s.rf_valid, s.snr0, 1, "dB");
            kv_f("snr1", s.rf_valid, s.snr1, 1, "dB");
            kv_f("rsrq", s.rf_valid, s.rsrq, 1, "dB");
            kv_f("rssi", s.rf_valid, s.rssi, 1, "dBm");
            kv_l("ncells", s.nnb);
            kv_f("nb_earfcn", bn >= 0, bn >= 0 ? s.nb[bn].earfcn : 0, 0, "");
            kv_f("nb_pci", bn >= 0, bn >= 0 ? s.nb[bn].pci : 0, 0, "");
            kv_f("nb_rsrp", bn >= 0, bn >= 0 ? mean(&s.nb[bn].rsrp) : 0, 1, "dBm");
            kv_f("nb_rsrq", bn >= 0 && s.nb[bn].rsrq.n > 0, bn >= 0 ? mean(&s.nb[bn].rsrq) : 0, 1, "dB");
            kv_f("ho_margin", hm, margin, 1, "dB");
            kv_f("rlm_oos", s.rlm_oos.n > 0, mean(&s.rlm_oos), 0, "%");
            kv_f("t310", s.rlm_oos.n > 0, s.t310, 0, "");
            kv_end();
        } else {
            char gs[96], ns[48], c1[16], c2[16], c3[16], c4[16], c5[16];
            snprintf(gs, sizeof(gs), "%s %11.2f %s %s %s %s", pct(c1, s.ul_nack, nph), s.grant_rx * 8 / el / 1e6,
                     pct(c2, s.grant_used, s.grant_rx), avg(c3, &s.ul_txpwr, 5),
                     s.pathloss.n ? (sprintf(c4, "%4.0f", mean(&s.pathloss)), c4) : "   -", avg(c5, &s.pc_corr, 5));
            if (hm) snprintf(ns, sizeof(ns), "%5d %6.1f %6.1f", s.nb[bn].pci, mean(&s.nb[bn].rsrp), margin);
            else snprintf(ns, sizeof(ns), "    -      -      -");
            printf("%s | %5ld  %s %5ld %s %4ld  %s %s %s %5.1f | %5zu %5ld %s %6.2f %s %5s %s %s %s | %s | %s | %s/%s %s | %s | %s | %s\n",
                   tm, s.dl_tb, pct(b1, s.dl_first_fail, s.dl_first), s.dl_retx, pct(b13, s.dl_retx, s.dl_tb), s.dl_resid,
                   avg(b2, &s.mcs, 4), avg(b3, &s.rbs, 5), pct(b4, s.ntb[2], s.ntb[1] + s.ntb[2]), dlm,
                   s.ul_n, ulr, pct(b5, ulr, s.ul_n), ulm, avg(b6, &s.ul_rb, 5), s.ul_n ? MODS[m] : "-",
                   s.ul_rate.n ? (sprintf(b7, "%5.2f", mean(&s.ul_rate)), b7) : "    -",
                   avg(b8, &s.ul_pwr, 4), pct(b9, s.ul_pwrlim, s.ul_n), gs, qs,
                   avg(b10, &s.cqi, 4), avg(b11, &s.cqi1, 4),
                   s.ri[1] + s.ri[2] ? (sprintf(b12, "%4.1f", (s.ri[1] + 2.0 * s.ri[2]) / (s.ri[1] + s.ri[2])), b12) : "   -",
                   tv, rf, ns);
        }
        fflush(stdout);

        tot_t += el;
        tot_dl_bytes += s.dl_ok_bytes;
        tot_ul_bytes += s.ul_bytes;
        tot_dltb += s.dl_tb;
        tot_first += s.dl_first;
        tot_fail += s.dl_first_fail;
        tot_retx += s.dl_retx;
        tot_resid += s.dl_resid;
        tot_ultx += s.ul_n;
        tot_ulretx += ulr;
        tot_pwrlim += s.ul_pwrlim;
        tot_grx += s.grant_rx;
        tot_gused += s.grant_used;
        tot_ack += s.ul_ack;
        tot_nack += s.ul_nack;
        for (int k = 0; k < L2_N; k++) tot_l2[k] += s.l2[k];
        tot_t310 += s.t310;
        if (s.ul_buf.n && s.ul_buf.max > tot_bufmax) tot_bufmax = s.ul_buf.max;
        if (s.pathloss.n) {
            double pl = mean(&s.pathloss);
            if (!have_pl || pl < pl_min) pl_min = pl;
            if (!have_pl || pl > pl_max) pl_max = pl;
            have_pl = 1;
        }
        if (dlm > peak_dl) peak_dl = dlm;
        if (ulm > peak_ul) peak_ul = ulm;
        stats_reset(&s);
        s.ul_n = 0;
    }
    diag_disable_logs(&d);
    if (tot_t <= 0) tot_t = 1;
    if (!table) {
        kv_start(hl.model);
        kv_s("event", "summary");
        kv_f("duration", 1, tot_t, 0, "s");
        kv_f("dl_total", 1, tot_dl_bytes / 1e6, 1, "MB");
        kv_f("dl_avg", 1, tot_dl_bytes * 8 / tot_t / 1e6, 2, "Mbps");
        kv_f("dl_peak", 1, peak_dl, 2, "Mbps");
        kv_f("dl_bler", tot_first > 0, 100.0 * tot_fail / (tot_first ? tot_first : 1), 1, "%");
        kv_l("dl_harq_retx", tot_retx);
        kv_f("dl_harq_retx_pct", tot_dltb > 0, 100.0 * tot_retx / (tot_dltb ? tot_dltb : 1), 1, "%");
        kv_l("dl_resid", tot_resid);
        kv_f("ul_total", 1, tot_ul_bytes / 1e6, 1, "MB");
        kv_f("ul_avg", 1, tot_ul_bytes * 8 / tot_t / 1e6, 2, "Mbps");
        kv_f("ul_peak", 1, peak_ul, 2, "Mbps");
        kv_l("ul_harq_retx", tot_ulretx);
        kv_f("ul_harq_retx_pct", tot_ultx > 0, 100.0 * tot_ulretx / (tot_ultx ? tot_ultx : 1), 1, "%");
        kv_l("ul_nack", tot_nack);
        kv_f("ul_nack_pct", tot_ack + tot_nack > 0, 100.0 * tot_nack / (tot_ack + tot_nack ? tot_ack + tot_nack : 1), 1, "%");
        kv_f("ul_pwrlim", tot_ultx > 0, 100.0 * tot_pwrlim / (tot_ultx ? tot_ultx : 1), 1, "%");
        kv_f("ul_grant_used", tot_grx > 0, 100.0 * tot_gused / (tot_grx ? tot_grx : 1), 1, "%");
        kv_f("pathloss_min", have_pl, pl_min, 0, "dB");
        kv_f("pathloss_max", have_pl, pl_max, 0, "dB");
        kv_f("ul_buf_max", 1, tot_bufmax / 1000, 1, "KB");
        kv_f("qdelay_max", 1, tot_qmax, 0, "ms");
        kv_l("qwarn_intervals", tot_qwarn);
        kv_l("intervals", n_int);
        kv_l("rlc_ul_retx", tot_l2[RLC_UL_RETX]);
        kv_l("rlc_ul_nack", tot_l2[RLC_UL_NACK]);
        kv_l("rlc_dl_retx", tot_l2[RLC_DL_RETX]);
        kv_l("rlc_dl_nack", tot_l2[RLC_DL_NACK]);
        kv_l("rlc_dl_drop", tot_l2[RLC_DL_DROP]);
        kv_l("pdcp_ul_discard", tot_l2[PDCP_UL_DISCARD]);
        kv_l("t310_intervals", tot_t310);
        kv_l("rrc_setups", mob.counts[MOB_SETUP]);
        kv_l("rrc_releases", mob.counts[MOB_RELEASE]);
        kv_l("meas_reports", mob.counts[MOB_REPORT]);
        kv_l("handovers", mob.counts[MOB_HO]);
        kv_l("handovers_done", mob.counts[MOB_HO_DONE]);
        kv_l("reestablishments", mob.counts[MOB_REEST]);
        kv_f("temp_min", seen_t, tmin, 0, "C");
        kv_f("temp_max", seen_t, tmax, 0, "C");
        kv_f("vbat_min", seen_v, vmin, 2, "V");
        kv_f("vbat_max", seen_v, vmax, 2, "V");
        kv_end();
        return 0;
    }
    printf("\n--- %.0f s total ---\n", tot_t);
    printf("DL: %.1f MB, avg %.1f / peak %.1f Mbit/s, BLER1st %s, HARQ retx %ld (%s of TBs), %ld residual\n",
           tot_dl_bytes / 1e6, tot_dl_bytes * 8 / tot_t / 1e6, peak_dl, trim_pct(pct(b1, tot_fail, tot_first)), tot_retx,
           trim_pct(pct(b4, tot_retx, tot_dltb)), tot_resid);
    printf("UL: %.1f MB, avg %.1f / peak %.1f Mbit/s, HARQ retx %ld (%s of PUSCH), power-limited %s of PUSCH\n",
           tot_ul_bytes / 1e6, tot_ul_bytes * 8 / tot_t / 1e6, peak_ul, tot_ulretx, trim_pct(pct(b2, tot_ulretx, tot_ultx)),
           trim_pct(pct(b3, tot_pwrlim, tot_ultx)));
    printf("UL HARQ NACK (PHICH) %s, grant used %s, path loss ", trim_pct(pct(b5, tot_nack, tot_ack + tot_nack)),
           trim_pct(pct(b6, tot_gused, tot_grx)));
    if (have_pl) printf("%.0f..%.0f dB\n", pl_min, pl_max);
    else printf("-\n");
    printf("UL queue: max %.0f KB, max delay %.0f ms, %ld of %ld intervals with queue delay >= %d ms\n", tot_bufmax / 1000,
           tot_qmax, tot_qwarn, n_int, QDELAY_WARN);
    printf("Mobility: %ld handovers (%ld completed), %ld measurement reports, %ld connection setups, %ld releases, "
           "%ld re-establishments\n", mob.counts[MOB_HO], mob.counts[MOB_HO_DONE], mob.counts[MOB_REPORT],
           mob.counts[MOB_SETUP], mob.counts[MOB_RELEASE], mob.counts[MOB_REEST]);
    printf("RLC: UL retx %ld, NACK rx %ld; DL retx %ld, NACK tx %ld, dropped %ld, t-reordering expiries %ld; "
           "PDCP UL discards %ld; T310 running in %ld intervals\n", tot_l2[RLC_UL_RETX], tot_l2[RLC_UL_NACK],
           tot_l2[RLC_DL_RETX], tot_l2[RLC_DL_NACK], tot_l2[RLC_DL_DROP], tot_l2[RLC_DL_TREORD], tot_l2[PDCP_UL_DISCARD],
           tot_t310);
    if (seen_t || seen_v)
        printf("Modem: temperature %d..%d degC, supply %.2f..%.2f V\n", tmin, tmax, vmin, vmax);
    return 0;
}
