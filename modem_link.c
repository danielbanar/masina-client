/* Live LTE link-quality monitor for SIM7600 (Qualcomm MDM9x07) over DIAG (/dev/ttyUSB0).
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
 *   Modem temperature / supply voltage via AT (AT+CPMUTEMP, AT+CBC) every 5 s; '-' if the AT port is busy.
 *
 * Output: one line per interval, "SIM7600G-H;name=value<unit>;...", fields always in the same order, NA = no data.
 *   Event lines: ...;event=cell_change;... and on exit ...;event=summary;...   --table prints the old column view.
 *   The key=value lines are also sent over UDP to GROUND_IP from /etc/masina.conf, port 2224 (same as the SSC
 *   telemetry from masinatelemetry; the ground tells them apart by the first field).
 *
 * usage: modem_link [interval_s] [diag_port] [at_port] [--table]      Ctrl-C prints totals and exits
 */
#include <netdb.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include "lte_common.h"

static volatile sig_atomic_t stop;
static void on_sig(int s) { (void)s; stop = 1; }

static const char *HEADER =
    "         |---------------------------- downlink ----------------------------|"
    "--------------------------- uplink ----------------------------|------ UL queue -------|  CSI          | modem   |\n"
    "time     |   TBs  BLER1st HARQretx    resid  MCS   RBs  MIMO%  Mbit |"
    "    tx HARQretx       Mbit   RBs   mod  rate  pwr  pwr>23 | BSR KB qdly ms qmax PHR | CQI0/1    RI  | degC  V  | EARFCN PCI  RSRP0/1 dBm  diff   SNR0/1 dB    RSRQ  RSSI";

/* modem temperature and supply voltage over AT, polled every HEALTH_PERIOD s */
#define HEALTH_PERIOD 5
typedef struct {
    int fd;
    double last;
    int have_t, have_v;
    int temp, tmin, tmax;
    double volt, vmin, vmax;
    char model[64];
} health_t;

static void health_open(health_t *h, const char *port)
{
    const char *c[] = { port, "/dev/ttyUSB2", "/dev/ttyUSB3" };
    h->fd = -1;
    h->last = -1e9;
    for (int i = port ? 0 : 1; i < 3 && h->fd < 0; i++)
        h->fd = tty_open(c[i]);
    /* model from AT+CGMM, e.g. SIMCOM_SIM7600G-H -> SIM7600G-H */
    char v[128];
    snprintf(h->model, sizeof(h->model), "SIM7600G-H");
    if (at_val(h->fd, "AT+CGMM", NULL, v, sizeof(v))) {
        const char *m = strncmp(v, "SIMCOM_", 7) ? v : v + 7;
        if (*m && !strchr(m, ' ') && !strchr(m, ':')) snprintf(h->model, sizeof(h->model), "%s", m);
    }
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

/* ---- UDP copy of the key=value lines to the ground station */
#define MASINA_CONF "/etc/masina.conf"
#define GROUND_PORT "2224"

static int udp_fd = -1;
static struct sockaddr_storage udp_addr;
static socklen_t udp_addrlen;

/* GROUND_IP from masina.conf (IP or hostname); without it the lines only go to stdout */
static void udp_open(void)
{
    FILE *f = fopen(MASINA_CONF, "r");
    if (!f) {
        fprintf(stderr, "warning: %s not found, UDP output disabled\n", MASINA_CONF);
        return;
    }
    char buf[256], host[128] = "";
    while (fgets(buf, sizeof(buf), f))
        if (sscanf(buf, "GROUND_IP=%127s", host) == 1) break;
    fclose(f);
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

static void kv_end(void)
{
    puts(line);
    fflush(stdout);
    if (udp_fd >= 0) {
        /* one datagram per line, newline-terminated like the SSC lines */
        struct iovec iov[2] = { { line, strlen(line) }, { "\n", 1 } };
        struct msghdr msg = { .msg_name = &udp_addr, .msg_namelen = udp_addrlen, .msg_iov = iov, .msg_iovlen = 2 };
        sendmsg(udp_fd, &msg, 0);
    }
}

static void health_poll(health_t *h)
{
    if (h->fd < 0 || now() - h->last < HEALTH_PERIOD)
        return;
    h->last = now();
    char v[128];
    int ht = at_val(h->fd, "AT+CPMUTEMP", "+CPMUTEMP", v, sizeof(v)) != NULL;
    if (ht) {
        h->temp = atoi(v);
        if (!h->have_t || h->temp < h->tmin) h->tmin = h->temp;
        if (!h->have_t || h->temp > h->tmax) h->tmax = h->temp;
        h->have_t = 1;
    }
    int hv = at_val(h->fd, "AT+CBC", "+CBC", v, sizeof(v)) != NULL;
    if (hv) {
        h->volt = atof(v);
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

    int codes[] = { LOG_PDSCH & 0xfff, LOG_PUSCH & 0xfff, LOG_MAC_UL & 0xfff, LOG_CSI & 0xfff, LOG_MEAS & 0xfff };
    if (diag_set_log_mask(&d, 0xB, codes, 5) < 0)
        fprintf(stderr, "warning: no response to log mask command on %s (is it the DIAG port?)\n", port);

    static health_t hl;
    health_open(&hl, args[2]);
    if (!table)
        udp_open();
    int seen_t = 0, seen_v = 0, tmin = 0, tmax = 0;
    double vmin = 0, vmax = 0;

    static stats_t s;
    double tot_t = 0, peak_dl = 0, peak_ul = 0;
    long long tot_dl_bytes = 0, tot_ul_bytes = 0;
    long tot_dltb = 0, tot_first = 0, tot_fail = 0, tot_retx = 0, tot_resid = 0, tot_ultx = 0, tot_ulretx = 0, tot_pwrlim = 0, tot_qwarn = 0;
    double tot_qmax = 0;
    int have_cell = 0, cell_e = 0, cell_p = 0;
    char b1[32], b2[32], b3[32], b4[32], b5[32], b6[32], b7[32], b8[32], b9[32], b10[32], b11[32], b12[32];

    long n_int = 0;
    for (long n = 0; !stop; n++, n_int++) {
        double t0 = now(), end = t0 + interval;
        int code, len;
        const uint8_t *body;
        while (!stop && (len = diag_log(&d, end, &code, &body)) != -2) {
            if (len >= 0) stats_dispatch(&s, code, body, len);
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
        int n0 = hq ? snprintf(qs, sizeof(qs), "%6.1f %6.0f%c %4.0f ", mean(&s.bsr) / 1000, qd, stats_queue_warn(&s, el) ? '!' : ' ', qm)
                    : snprintf(qs, sizeof(qs), "     -      -     -  ");
        snprintf(qs + n0, sizeof(qs) - n0, s.phr.n ? "%3.0f" : "  -", mean(&s.phr));
        if (hq) { if (qm > tot_qmax) tot_qmax = qm; tot_qwarn += stats_queue_warn(&s, el); }
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
            kv_l("ul_tx", (long)s.ul_n);
            kv_l("ul_harq_retx", ulr);
            kv_f("ul_harq_retx_pct", s.ul_n > 0, 100.0 * ulr / (s.ul_n ? s.ul_n : 1), 1, "%");
            kv_f("ul_rate", 1, ulm, 2, "Mbps");
            kv_f("ul_rbs", s.ul_rb.n > 0, mean(&s.ul_rb), 1, "");
            kv_s("ul_mod", s.ul_n && m ? MODS[m] : "NA");
            kv_f("ul_coderate", s.ul_rate.n > 0, mean(&s.ul_rate), 2, "");
            kv_f("ul_pwr", s.ul_pwr.n > 0, mean(&s.ul_pwr), 1, "dBm");
            kv_f("ul_pwrlim", s.ul_n > 0, 100.0 * s.ul_pwrlim / (s.ul_n ? s.ul_n : 1), 1, "%");
            kv_f("bsr", s.bsr.n > 0, mean(&s.bsr) / 1000, 1, "KB");
            kv_f("qdelay", hq, qd, 0, "ms");
            kv_f("qdelay_max", hq, qm, 0, "ms");
            kv_l("qwarn", stats_queue_warn(&s, el));
            kv_f("phr", s.phr.n > 0, mean(&s.phr), 0, "dB");
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
            kv_end();
        } else
        printf("%s | %5ld  %s %5ld %s %4ld  %s %s %s %5.1f | %5zu %5ld %s %6.2f %s %5s %s %s %s | %s | %s/%s %s | %s | %s\n",
               tm, s.dl_tb, pct(b1, s.dl_first_fail, s.dl_first), s.dl_retx, pct(b13, s.dl_retx, s.dl_tb), s.dl_resid,
               avg(b2, &s.mcs, 4), avg(b3, &s.rbs, 5), pct(b4, s.ntb[2], s.ntb[1] + s.ntb[2]), dlm,
               s.ul_n, ulr, pct(b5, ulr, s.ul_n), ulm, avg(b6, &s.ul_rb, 5), s.ul_n ? MODS[m] : "-",
               s.ul_rate.n ? (sprintf(b7, "%5.2f", mean(&s.ul_rate)), b7) : "    -",
               avg(b8, &s.ul_pwr, 4), pct(b9, s.ul_pwrlim, s.ul_n), qs,
               avg(b10, &s.cqi, 4), avg(b11, &s.cqi1, 4),
               s.ri[1] + s.ri[2] ? (sprintf(b12, "%4.1f", (s.ri[1] + 2.0 * s.ri[2]) / (s.ri[1] + s.ri[2])), b12) : "   -",
               tv, rf);
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
        kv_f("ul_pwrlim", tot_ultx > 0, 100.0 * tot_pwrlim / (tot_ultx ? tot_ultx : 1), 1, "%");
        kv_f("qdelay_max", 1, tot_qmax, 0, "ms");
        kv_l("qwarn_intervals", tot_qwarn);
        kv_l("intervals", n_int);
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
    printf("UL queue: max delay %.0f ms, %ld of %.0f intervals with queue delay >= %d ms\n", tot_qmax, tot_qwarn,
           tot_t / interval, QDELAY_WARN);
    if (seen_t || seen_v)
        printf("Modem: temperature %d..%d degC, supply %.2f..%.2f V\n", tmin, tmax, vmin, vmax);
    return 0;
}
