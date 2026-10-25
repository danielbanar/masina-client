/* Shared code for modem_link / lte_info: Qualcomm DIAG transport, AT commands and
 * PHY/MAC/RLC/PDCP log parsers for SIM7600 / Quectel EC25 (MDM9x07). Plain C99 + POSIX, no dependencies. */
#ifndef LTE_COMMON_H
#define LTE_COMMON_H
#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/select.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

/* ------------------------------------------------------------------ misc */
static double now(void) /* monotonic: durations and deadlines only, not a time of day */
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

/* time of day for printed timestamps */
__attribute__((unused)) static double wall_time(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static inline uint16_t rd16(const uint8_t *p) { return p[0] | p[1] << 8; }
static inline uint32_t rd32(const uint8_t *p) { return p[0] | p[1] << 8 | p[2] << 16 | (uint32_t)p[3] << 24; }

/* little-endian bit field: width w bits starting at bit off of buffer p */
static uint32_t bits(const uint8_t *p, int off, int w)
{
    uint32_t v = 0;
    for (int i = 0; i < w; i++) {
        int b = off + i;
        v |= (uint32_t)((p[b >> 3] >> (b & 7)) & 1) << i;
    }
    return v;
}

typedef struct { double sum, min, max; long n; } acc_t;

static void acc(acc_t *a, double v)
{
    if (!a->n || v < a->min) a->min = v;
    if (!a->n || v > a->max) a->max = v;
    a->sum += v;
    a->n++;
}

static double mean(const acc_t *a) { return a->n ? a->sum / a->n : 0; }

static int tty_open(const char *port)
{
    int fd = open(port, O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (fd < 0)
        return -1;
    struct termios t;
    if (tcgetattr(fd, &t) == 0) {
        cfmakeraw(&t);
        t.c_cflag |= CLOCAL | CREAD;
        cfsetispeed(&t, B115200);
        cfsetospeed(&t, B115200);
        tcsetattr(fd, TCSANOW, &t);
    }
    tcflush(fd, TCIOFLUSH);
    return fd;
}

/* wait up to `timeout` s for fd to become readable; 1 readable, 0 timeout, -1 interrupted/error */
static int wait_readable(int fd, double timeout)
{
    if (timeout < 0)
        timeout = 0;
    fd_set rs;
    FD_ZERO(&rs);
    FD_SET(fd, &rs);
    struct timeval tv = { (long)timeout, (long)((timeout - (long)timeout) * 1e6) };
    return select(fd + 1, &rs, NULL, NULL, &tv);
}

/* ------------------------------------------------------------------ DIAG (HDLC over tty) */
typedef struct {
    int fd;
    uint8_t buf[1 << 18];
    size_t n;
    uint8_t frame[1 << 16];
} diag_t;

static uint16_t crc16(const uint8_t *d, size_t n)
{
    uint16_t c = 0xffff;
    while (n--) {
        c ^= *d++;
        for (int i = 0; i < 8; i++)
            c = (c & 1) ? (c >> 1) ^ 0x8408 : c >> 1;
    }
    return ~c;
}

static int diag_send(diag_t *d, const uint8_t *p, size_t n)
{
    uint8_t o[4096];
    size_t k = 0;
    uint16_t c = crc16(p, n);
    uint8_t tail[2] = { c & 0xff, c >> 8 };
    for (size_t i = 0; i < n + 2 && k < sizeof(o) - 3; i++) {
        uint8_t b = i < n ? p[i] : tail[i - n];
        if (b == 0x7e || b == 0x7d) {
            o[k++] = 0x7d;
            o[k++] = b ^ 0x20;
        } else
            o[k++] = b;
    }
    o[k++] = 0x7e;
    return write(d->fd, o, k) == (ssize_t)k ? 0 : -1;
}

/* next valid HDLC frame into d->frame; returns length, 0 on timeout, -1 on interrupt/error */
static int diag_frame(diag_t *d, double deadline)
{
    for (;;) {
        uint8_t *e = memchr(d->buf, 0x7e, d->n);
        while (e) {
            size_t fl = e - d->buf, k = 0;
            int esc = 0;
            for (size_t i = 0; i < fl && k < sizeof(d->frame); i++) {
                uint8_t b = d->buf[i];
                if (esc) { d->frame[k++] = b ^ 0x20; esc = 0; }
                else if (b == 0x7d) esc = 1;
                else d->frame[k++] = b;
            }
            memmove(d->buf, e + 1, d->n - fl - 1);
            d->n -= fl + 1;
            if (k >= 3 && crc16(d->frame, k - 2) == rd16(d->frame + k - 2))
                return (int)(k - 2);
            e = memchr(d->buf, 0x7e, d->n);
        }
        if (d->n == sizeof(d->buf))
            d->n = 0;  /* garbage without delimiter */
        int r = wait_readable(d->fd, deadline - now());
        if (r < 0)
            return errno == EINTR ? -1 : -1;
        if (r == 0)
            return 0;
        ssize_t got = read(d->fd, d->buf + d->n, sizeof(d->buf) - d->n);
        if (got > 0)
            d->n += got;
    }
}

static int diag_cmd(diag_t *d, const uint8_t *p, size_t n, double timeout)
{
    diag_send(d, p, n);
    double end = now() + timeout;
    int l;
    while ((l = diag_frame(d, end)) > 0)
        if (d->frame[0] == p[0])
            return l;
    return -1;
}

static int diag_open(diag_t *d, const char *port)
{
    d->n = 0;
    d->fd = tty_open(port);
    return d->fd < 0 ? -1 : 0;
}

/* enable log items (12-bit item numbers within equipment id, e.g. 0x173 for 0xB173) */
static int diag_set_log_mask(diag_t *d, int equip, const int *codes, int nc)
{
    int maxc = 0;
    for (int i = 0; i < nc; i++)
        if (codes[i] > maxc) maxc = codes[i];
    int items = maxc + 1, mb = (items + 7) / 8;
    uint8_t p[16 + 512] = { 0x73, 0, 0, 0, 3, 0, 0, 0 };
    p[8] = equip;
    p[12] = items & 0xff;
    p[13] = items >> 8;
    for (int i = 0; i < nc; i++)
        p[16 + codes[i] / 8] |= 1 << (codes[i] % 8);
    return diag_cmd(d, p, 16 + mb, 2) > 0 ? 0 : -1;
}

static void diag_disable_logs(diag_t *d)
{
    uint8_t p[8] = { 0x73, 0, 0, 0, 0, 0, 0, 0 };
    diag_cmd(d, p, sizeof(p), 1);
}

/* next log packet: returns body length (>=0) with code/body set, -2 timeout, -1 interrupted */
static int diag_log(diag_t *d, double deadline, int *code, const uint8_t **body)
{
    for (;;) {
        int l = diag_frame(d, deadline);
        if (l == 0) return -2;
        if (l < 0) return -1;
        if (d->frame[0] == 0x10 && l >= 16) {
            *code = rd16(d->frame + 6);
            *body = d->frame + 16;
            return l - 16;
        }
    }
}

/* modem time (s, 1.25 ms resolution) of the log packet whose payload diag_log() returned */
__attribute__((unused)) static double diag_log_time(const uint8_t *body)
{
    uint64_t ts = rd32(body - 8) | (uint64_t)rd32(body - 4) << 32;
    return (ts >> 16) * 1.25e-3;
}

/* ------------------------------------------------------------------ AT */
#define AT_MAXL 40
typedef char at_lines[AT_MAXL][512];

/* send cmd, collect response lines without echo/OK/unsolicited codes of other commands.
 * returns number of lines, -1 on ERROR or no port */
static int at_query(int fd, const char *cmd, at_lines out, double timeout)
{
    if (fd < 0)
        return -1;
    char buf[16384];
    size_t n = 0;
    tcflush(fd, TCIOFLUSH);
    char c[256];
    int cl = snprintf(c, sizeof(c), "%s\r", cmd);
    if (write(fd, c, cl) != cl)
        return -1;
    double end = now() + timeout;
    while (n < sizeof(buf) - 1) {
        double left = end - now();
        if (left <= 0) break;
        if (wait_readable(fd, left < 0.2 ? left : 0.2) > 0) {
            ssize_t r = read(fd, buf + n, sizeof(buf) - 1 - n);
            if (r > 0) n += r;
            buf[n] = 0;
            if (strstr(buf, "\r\nOK\r\n") || strstr(buf, "ERROR")) break;
        }
    }
    buf[n] = 0;
    /* command name, e.g. "+CPSI" */
    char name[32] = "";
    const char *s = cmd + 2;
    size_t k = 0;
    if (*s == '+' || *s == '$') name[k++] = *s++;
    while (isalnum((unsigned char)*s) && k < sizeof(name) - 1) name[k++] = toupper((unsigned char)*s++);
    name[k] = 0;
    if (k == 1) name[0] = 0;
    int nl = 0;
    for (char *save, *l = strtok_r(buf, "\r\n", &save); l; l = strtok_r(NULL, "\r\n", &save)) {
        while (isspace((unsigned char)*l)) l++;
        char *e = l + strlen(l);
        while (e > l && isspace((unsigned char)e[-1])) *--e = 0;
        if (!*l || !strcmp(l, "OK") || !strcmp(l, cmd)) continue;
        if (*l == '+') {
            /* keep only answers to this command: prefix like "+ICCID" must be part of "+CICCID" */
            char pre[32];
            size_t pl = strcspn(l + 1, ":");
            if (pl >= sizeof(pre)) pl = sizeof(pre) - 1;
            for (size_t i = 0; i < pl; i++) pre[i] = toupper((unsigned char)l[1 + i]);
            pre[pl] = 0;
            if (!name[0] || !pl || !strstr(name, pre)) continue;
        }
        if (strstr(l, "ERROR")) return -1;
        if (nl < AT_MAXL) snprintf(out[nl++], sizeof(out[0]), "%s", l);
    }
    return nl;
}

/* value of first line starting with prefix (text after ':'), or the first line if prefix NULL */
__attribute__((unused)) static const char *at_val(int fd, const char *cmd, const char *prefix, char *dst, size_t dsz)
{
    static at_lines L;
    int n = at_query(fd, cmd, L, 3);
    for (int i = 0; i < n; i++) {
        if (!prefix) { snprintf(dst, dsz, "%s", L[i]); return dst; }
        if (!strncmp(L[i], prefix, strlen(prefix))) {
            const char *v = strchr(L[i], ':');
            v = v ? v + 1 : L[i];
            while (*v == ' ') v++;
            snprintf(dst, dsz, "%s", v);
            return dst;
        }
    }
    return NULL;
}

/* model from the DIAG extended build id (e.g. EC25EUXGAR08A16M1G -> EC25); works while ModemManager holds AT */
__attribute__((unused)) static int diag_model(diag_t *d, char *dst, size_t dsz)
{
    uint8_t c = 0x7c;
    int l = diag_cmd(d, &c, 1, 2);
    if (l <= 12) return 0;
    char bid[128];
    int n = l - 12 < (int)sizeof(bid) - 1 ? l - 12 : (int)sizeof(bid) - 1;
    memcpy(bid, d->frame + 12, n);
    bid[n] = 0;
    if ((bid[0] == 'E' && strchr("CGM", bid[1]) && isdigit((unsigned char)bid[2]) && isdigit((unsigned char)bid[3])) ||
        (bid[0] == 'B' && bid[1] == 'G' && isdigit((unsigned char)bid[2]))) {
        snprintf(dst, dsz, "%.4s", bid);
        return 1;
    }
    const char *m = strstr(bid, "SIM");
    if (m && isdigit((unsigned char)m[3])) {
        size_t k = 3;
        while (m[k] && (isalnum((unsigned char)m[k]) || m[k] == '-')) k++;
        snprintf(dst, dsz, "%.*s", (int)k, m);
        return 1;
    }
    return 0;
}

/* Quectel (EC2x/EG/EM/BG/RM) vs SIMCom by model name */
__attribute__((unused)) static int is_quectel(const char *model)
{
    return (model[0] == 'E' && strchr("CGM", model[1]) && isdigit((unsigned char)model[2])) ||
           !strncmp(model, "BG", 2) || !strncmp(model, "RM", 2);
}

/* temperature: SIMCom "+CPMUTEMP: 33"; Quectel "+QTEMP: pmic,xo,pa" (hottest); -1000 if none */
__attribute__((unused)) static int parse_temp(const char *v)
{
    int best = -1000;
    for (const char *p = v; *p;) {
        if (*p == '-' || isdigit((unsigned char)*p)) {
            char *e;
            long x = strtol(p, &e, 10);
            if (x > -40 && x < 150 && x > best) best = x;
            p = e;
        } else
            p++;
    }
    return best;
}

/* supply voltage: SIMCom "+CBC: 4.21V"; Quectel "+CBC: 0,0,3812" (mV); <0 if none */
__attribute__((unused)) static double parse_volt(const char *v)
{
    const char *c = strrchr(v, ',');
    double x = atof(c ? c + 1 : v);
    return x > 100 ? x / 1000 : x > 0 ? x : -1;
}

/* ------------------------------------------------------------------ PHY/MAC log parsers */
#define LOG_PDSCH  0xB173  /* LTE PHY PDSCH stat indication v5 */
#define LOG_PUSCH  0xB139  /* LTE LL1 PUSCH tx report v25 */
#define LOG_MAC_UL 0xB064  /* LTE MAC UL transport block */
#define LOG_CSI    0xB14D  /* LTE PHY PUCCH CSI report v24 */
#define LOG_MEAS   0xB193  /* LTE ML1 serving cell meas response */
#define LOG_UL_BUF   0xB066  /* LTE MAC UL buffer status internal (subpacket v5): exact bytes queued, per subframe */
#define LOG_UL_TXST  0xB067  /* LTE MAC UL Tx statistics: grant bytes received / used per 100 subframes */
#define LOG_RLC_DL   0xB087  /* LTE RLC DL statistics (subpacket v3), cumulative per radio bearer */
#define LOG_RLC_UL   0xB097  /* LTE RLC UL statistics (subpacket v1) */
#define LOG_PDCP_UL  0xB0B4  /* LTE PDCP UL statistics (subpacket v3) */
#define LOG_PHICH    0xB16B  /* LTE PDCCH-PHICH indication report v5: UL HARQ ACK/NACK, PDCCH aggregation level */
#define LOG_PUSCH_PC 0xB16E  /* LTE PUSCH power control v5: actual tx power, path loss, closed-loop f(i) */
#define LOG_NCELL    0xB179  /* LTE ML1 connected mode intra-frequency measurement v4: neighbour cells */
#define LOG_RLM      0xB18A  /* LTE PHY radio link monitoring v1: out-of-sync BLER, T310 */
#define LOG_CONN_NB  0xB195  /* LTE ML1 connected neighbour meas request/response: all measured frequencies */
#define LOG_RRC_OTA  0xB0C0  /* LTE RRC OTA message (lte_rrc.h) */
#define LOG_RACH_TRIG 0xB061 /* LTE MAC RACH trigger */
#define LOG_RACH_ATT 0xB062  /* LTE MAC RACH attempt */

/* RLC/PDCP counters (increase over the interval, all radio bearers) */
enum { RLC_UL_RETX, RLC_UL_NACK, RLC_UL_TPOLL, RLC_DL_RETX, RLC_DL_NACK, RLC_DL_DROP, RLC_DL_TREORD, PDCP_UL_DISCARD, L2_N };
__attribute__((unused)) static const char *L2_NAME[L2_N] = { "rlc_ul_retx", "rlc_ul_nack", "rlc_ul_tpoll", "rlc_dl_retx",
    "rlc_dl_nack", "rlc_dl_drop", "rlc_dl_treord", "pdcp_ul_discard" };

typedef struct {
    struct { uint8_t valid, ndi, ok; } harq[16][2];  /* persists across resets */
    long dl_tb, dl_first, dl_first_fail, dl_retx, dl_resid;
    long long dl_ok_bytes;
    acc_t mcs, rbs, tbs;
    long ntb[3];         /* codewords per new-data subframe (2 = 2x2 spatial multiplexing) */
    long dl_mod[3];      /* QPSK/16QAM/64QAM from MCS, all C-RNTI TBs */
    uint16_t *ul_tx;
    size_t ul_n, ul_cap;
    uint8_t ul_new[10240 / 8], ul_txmap[10240 / 8];
    long long ul_bytes;
    acc_t ul_rb, ul_rate, ul_pwr;
    acc_t bsr, phr;      /* UL buffer status (bytes queued in the modem) and power headroom (dB) */
    long ul_pwrlim, ul_mod[4];
    acc_t cqi, cqi1;
    long ri[3];
    int rf_valid, rf_n;
    uint32_t earfcn;
    int pci;
    double rsrp0, rsrp1, snr0, snr1, rsrq, rssi;
    acc_t ul_buf;                    /* exact UL buffer bytes, one sample per subframe */
    long long grant_rx, grant_used;  /* UL grant bytes from the eNB / used */
    long ul_ack, ul_nack;            /* PHICH */
    acc_t pdcch_agg, ul_txpwr, pathloss, pc_corr;
    int l2_valid;                    /* an RLC/PDCP statistics packet arrived in this interval */
    long l2[L2_N];
    acc_t nb_srv;                    /* serving RSRP as seen by the neighbour measurement */
    struct { unsigned earfcn; int pci; acc_t rsrp, rsrq; } nb[16];  /* neighbours, all measured frequencies */
    int nnb;
    int have_srv_cell, srv_pci;      /* serving cell as seen by 0xB179 */
    unsigned srv_earfcn;
    acc_t rlm_oos;
    int t310;
    /* persist across resets: last cumulative RLC/PDCP counters per (log code, radio bearer) */
    struct { int code, rb; uint32_t v[4]; } l2_last[16];
    int nl2;
} stats_t;

__attribute__((unused)) static void stats_reset(stats_t *s)
{
    uint16_t *tx = s->ul_tx;
    size_t cap = s->ul_cap;
    __typeof__(s->harq) h;
    __typeof__(s->l2_last) l2;
    int nl2 = s->nl2;
    memcpy(h, s->harq, sizeof(h));
    memcpy(l2, s->l2_last, sizeof(l2));
    memset(s, 0, sizeof(*s));
    memcpy(s->harq, h, sizeof(h));
    memcpy(s->l2_last, l2, sizeof(l2));
    s->nl2 = nl2;
    s->ul_tx = tx;
    s->ul_cap = cap;
}

static void stats_pdsch(stats_t *s, const uint8_t *b, int len)
{
    if (len < 4 || b[0] != 5)
        return;
    for (int i = 0; i < b[1] && 24 + 20 * i <= len; i++) {
        const uint8_t *r = b + 4 + 20 * i;
        int nt = r[4] > 2 ? 2 : r[4], fresh = 0, brk = 0;
        for (int k = 0; k < nt; k++) {
            const uint8_t *t = r + 6 + 6 * k;
            int h = t[0], f2 = t[1], tbs = rd16(t + 2), mcs = t[4];
            if (f2 & 0xf) { brk = 1; break; }  /* not C-RNTI (SI/P/RA-RNTI) */
            int hid = h & 0xf, tbi = (f2 >> 4) & 1, ndi = (h >> 6) & 1, ok = h >> 7;
            __typeof__(s->harq[0][0]) *p = &s->harq[hid][tbi];
            int isnew = !p->valid || p->ndi != ndi;
            if (isnew && p->valid && !p->ok)
                s->dl_resid++;  /* previous TB on this process never decoded */
            p->valid = 1; p->ndi = ndi; p->ok = ok;
            s->dl_tb++;
            if (mcs < 29) {
                s->dl_mod[mcs < 10 ? 0 : mcs < 17 ? 1 : 2]++;
                acc(&s->tbs, tbs);
            }
            if (isnew) {
                fresh++;
                s->dl_first++;
                s->dl_first_fail += !ok;
                if (mcs < 29) acc(&s->mcs, mcs);
            } else
                s->dl_retx++;
            if (ok)
                s->dl_ok_bytes += tbs;
        }
        if (!brk && fresh) {
            acc(&s->rbs, r[11]);
            s->ntb[nt]++;
        }
    }
}

static void stats_pusch(stats_t *s, const uint8_t *b, int len)
{
    if (len < 8 || b[0] != 25)
        return;
    for (int i = 0; i < (len - 8) / 48; i++) {
        const uint8_t *r = b + 8 + 48 * i;
        uint16_t t = rd16(r);  /* SFN*10 + subframe */
        if (s->ul_n == s->ul_cap) {
            s->ul_cap = s->ul_cap ? s->ul_cap * 2 : 4096;
            s->ul_tx = realloc(s->ul_tx, s->ul_cap * sizeof(*s->ul_tx));
        }
        s->ul_tx[s->ul_n++] = t;
        if (t < 10240) s->ul_txmap[t >> 3] |= 1 << (t & 7);
        acc(&s->ul_rate, rd16(r + 2) / 1024.0);  /* code rate */
        acc(&s->ul_rb, bits(r, 89, 7));
        s->ul_mod[bits(r, 154, 2)]++;            /* 1 QPSK, 2 16QAM, 3 64QAM */
        int p = (int8_t)r[24];                   /* requested PUSCH power, dBm */
        acc(&s->ul_pwr, p);
        s->ul_pwrlim += p > 23;
    }
}

/* 36.321 Table 6.1.3.1-1: buffer size upper bound per BSR index (63 = more than 150 KB) */
static const int BSR_BYTES[64] = { 0, 10, 12, 14, 17, 19, 22, 26, 31, 36, 42, 49, 57, 67, 78, 91, 107, 125, 146, 171, 200,
    234, 274, 321, 376, 440, 515, 603, 706, 826, 967, 1132, 1326, 1552, 1817, 2127, 2490, 2915, 3413, 3995, 4677, 5476,
    6411, 7505, 8787, 10287, 12043, 14099, 16507, 19325, 22624, 26487, 31009, 36304, 42502, 49759, 58255, 68201, 79846,
    93479, 109439, 128125, 150000, 150001 };

/* BSR (bytes, -1 if absent) and PHR (dB, -100 if absent) from a logged UL MAC header (subheaders + control elements) */
static void mac_ce(const uint8_t *h, int n, int *bsr, int *phr)
{
    int subs[32], ns = 0, i = 0;
    *bsr = -1;
    *phr = -100;
    while (i < n && ns < 32) {
        int e = h[i] >> 5 & 1, lcid = h[i] & 0x1f;
        i++;
        if (e && lcid <= 10 && i < n)  /* SDU subheader with length field */
            i += h[i] >> 7 ? 2 : 1;
        subs[ns++] = lcid;
        if (!e) break;
    }
    for (int k = 0; k < ns; k++) {  /* control elements follow the subheaders, in the same order */
        int lcid = subs[k];
        if ((lcid == 26 || lcid == 28 || lcid == 29) && i < n) {
            int v = h[i++] & 0x3f;
            if (lcid == 26) *phr = v - 23;
            else *bsr = BSR_BYTES[v];
        } else if (lcid == 30 && i + 3 <= n) {  /* long BSR: 4 logical channel groups */
            uint32_t v = (uint32_t)h[i] << 16 | h[i + 1] << 8 | h[i + 2];
            i += 3;
            *bsr = BSR_BYTES[v >> 18 & 0x3f] + BSR_BYTES[v >> 12 & 0x3f] + BSR_BYTES[v >> 6 & 0x3f] + BSR_BYTES[v & 0x3f];
        } else if (lcid == 27)
            i += 2;
    }
}

static void stats_mac_ul(stats_t *s, const uint8_t *b, int len)
{
    int pos = 4;
    for (int i = 0; len >= 2 && i < b[1] && pos + 4 <= len; i++) {
        int sid = b[pos], ver = b[pos + 1], sz = rd16(b + pos + 2);
        const uint8_t *body = b + pos + 4;
        if (sz > len - pos - 4) sz = len - pos - 4;  /* size field counts its own header on this firmware */
        pos += 4 + sz;
        if (sid != 8 || ver != 1 || sz < 1) continue;
        int p = 1;
        for (int j = 0; j < body[0] && p + 12 <= sz; j++) {
            int sfsf = rd16(body + p + 2), grant = rd16(body + p + 4), pad = rd16(body + p + 7);
            int t = ((sfsf >> 4) % 1024) * 10 + (sfsf & 15);
            if (t < 10240) s->ul_new[t >> 3] |= 1 << (t & 7);
            s->ul_bytes += grant - pad;
            int hl = body[p + 11], bsr, phr;
            if (hl > sz - p - 12) hl = sz - p - 12;
            mac_ce(body + p + 12, hl, &bsr, &phr);
            if (bsr >= 0) acc(&s->bsr, bsr);
            if (phr > -100) acc(&s->phr, phr);
            p += 12 + body[p + 11];
        }
    }
}

static void stats_csi(stats_t *s, const uint8_t *b, int len)
{
    if (len < 7)
        return;
    if ((b[3] & 0xf) == 4) {  /* wideband CQI/PMI report: CQI codeword 0, codeword 1 (0 when rank 1) */
        int v = b[5] | b[6] << 8;
        acc(&s->cqi, v >> 2 & 0xf);
        if (v >> 6 & 0xf) acc(&s->cqi1, v >> 6 & 0xf);
    } else if ((b[3] & 0xf) == 6)  /* rank indicator report */
        s->ri[(b[4] >> 7) + 1]++;
}

static void stats_meas(stats_t *s, const uint8_t *b, int len)
{
    if (len < 8 + 84 || b[4] != 0x19)
        return;
    uint32_t w[21];
    for (int i = 0; i < 21; i++) w[i] = rd32(b + 8 + 4 * i);
    if (s->rf_valid && (s->earfcn != w[0] || s->pci != (int)(w[1] & 0x1ff)))
        s->rf_n = 0;  /* new cell: don't mix measurements */
    double v[6] = {
        (w[6] & 0xfff) / 16.0 - 180,          /* RSRP RX0 */
        (w[7] & 0xfff) / 16.0 - 180,          /* RSRP RX1 */
        (w[17] & 0x1ff) / 10.0 - 20,          /* SNR RX0, approximate */
        ((w[17] >> 9) & 0x1ff) / 10.0 - 20,   /* SNR RX1, approximate */
        (w[9] >> 20 & 0x3ff) / 16.0 - 30,     /* combined RSRQ (matches AT+CPSI) */
        (w[11] & 0x7ff) / 16.0 - 110,         /* combined RSSI, both antennas (matches AT+CPSI) */
    };
    double *dst[6] = { &s->rsrp0, &s->rsrp1, &s->snr0, &s->snr1, &s->rsrq, &s->rssi };
    /* single samples (~50/s) are noisy (RSRQ +-3 dB): keep the running mean over the interval */
    s->rf_n++;
    for (int i = 0; i < 6; i++)
        *dst[i] = s->rf_n == 1 ? v[i] : *dst[i] + (v[i] - *dst[i]) / s->rf_n;
    s->rf_valid = 1;
    s->earfcn = w[0];
    s->pci = w[1] & 0x1ff;
}

/* ---- extra MAC/RLC/PDCP/PHY items (Qualcomm MDM9x07, verified on Quectel EC25) */

/* subpackets of a MAC/RLC/PDCP log packet (header: ver, count, 2 reserved; size field includes its own 4-byte header) */
typedef struct { const uint8_t *b; int len, i, pos; } subpkt_it;

static int subpkt_next(subpkt_it *it, int *ver, const uint8_t **p, int *pl)
{
    if (it->len < 2 || it->i >= it->b[1] || it->pos + 4 > it->len) return 0;
    int sz = rd16(it->b + it->pos + 2);
    if (sz < 4 || sz > it->len - it->pos) sz = it->len - it->pos;
    *ver = it->b[it->pos + 1];
    *p = it->b + it->pos + 4;
    *pl = sz - 4;
    it->pos += sz;
    it->i++;
    return 1;
}

static void stats_ul_buf(stats_t *s, const uint8_t *b, int len)
{
    int ver, pl;
    const uint8_t *p;
    subpkt_it it = { b, len, 0, 4 };
    while (subpkt_next(&it, &ver, &p, &pl)) {
        if (ver != 5 || pl < 1) continue;
        for (int k = 0, q = 1; k < p[0] && q + 3 <= pl; k++) {
            int nl = p[q + 2];
            double tot = 0;
            q += 3;
            int bad = 0;
            for (int j = 0; j < nl && q + 16 <= pl; j++, q += 16) {  /* lcid, prio, new (2 fields), retx, ctrl bytes */
                int32_t n1 = (int32_t)rd32(p + q + 2), n2 = (int32_t)rd32(p + q + 6), rt = (int32_t)rd32(p + q + 10);
                bad |= n1 < 0 || n2 < 0 || rt < 0;
                tot += (double)n1 + n2 + rt + rd16(p + q + 14);
            }
            /* a counter that briefly went negative (seen once during a band search) read as ~4 GB: drop the sample */
            if (!bad) acc(&s->ul_buf, tot);
        }
    }
}

static void stats_ul_txst(stats_t *s, const uint8_t *b, int len)
{
    if (len < 21 || b[5] != 1) return;
    uint32_t rx = rd32(b + 13), used = rd32(b + 17);
    if (used <= rx) { s->grant_rx += rx; s->grant_used += used; }
}

static void stats_phich(stats_t *s, const uint8_t *b, int len)
{
    if (len < 4 || b[0] != 5) return;
    for (int i = 0; i < b[3] && 4 + 40 * (i + 1) <= len; i++) {
        const uint8_t *r = b + 4 + 40 * i;
        uint32_t w0 = rd32(r), w1 = rd32(r + 4);
        if (w0 >> 17 & 1) {  /* PHICH received for an earlier PUSCH */
            if (w1 >> 4 & 1) s->ul_ack++;
            else s->ul_nack++;
        }
        for (int k = 0; k < (int)(w0 & 7); k++)
            acc(&s->pdcch_agg, 1 << (r[9 + 4 * k] >> 6 & 3));
    }
}

static void stats_pusch_pc(stats_t *s, const uint8_t *b, int len)
{
    if (len < 4 || b[0] != 5) return;
    for (int i = 0; i < b[3] && 4 + 12 * (i + 1) <= len; i++) {
        const uint8_t *r = b + 4 + 12 * i;
        uint32_t w1 = rd32(r + 4), w2 = rd32(r + 8);
        int fi = w2 & 1023, act = w2 >> 15 & 255;
        acc(&s->ul_txpwr, act > 127 ? act - 256 : act);
        acc(&s->pathloss, w1 >> 22 & 255);
        acc(&s->pc_corr, fi >= 512 ? fi - 1024 : fi);
    }
}

typedef struct { int idx, off1, off2; } l2cnt_t;  /* counter, payload offsets of the u32 value(s) summed (-1 = none) */
static const l2cnt_t RLC_DL_C[] = { { RLC_DL_RETX, 42, -1 }, { RLC_DL_NACK, 110, 114 }, { RLC_DL_DROP, 66, 78 }, { RLC_DL_TREORD, 118, -1 } };
static const l2cnt_t RLC_UL_C[] = { { RLC_UL_RETX, 30, -1 }, { RLC_UL_NACK, 42, 46 }, { RLC_UL_TPOLL, 58, -1 } };
static const l2cnt_t PDCP_UL_C[] = { { PDCP_UL_DISCARD, 53, -1 } };

/* counters are cumulative per radio bearer: add the increase since the previous packet */
static void stats_l2(stats_t *s, int code, const uint8_t *b, int len)
{
    int want, hdr, size, nc, ver, pl;
    const l2cnt_t *c;
    const uint8_t *p;
    if (code == LOG_RLC_DL) { want = 3; hdr = 9; size = 262; c = RLC_DL_C; nc = 4; }
    else if (code == LOG_RLC_UL) { want = 1; hdr = 5; size = 126; c = RLC_UL_C; nc = 3; }
    else { want = 3; hdr = 5; size = 253; c = PDCP_UL_C; nc = 1; }
    subpkt_it it = { b, len, 0, 4 };
    while (subpkt_next(&it, &ver, &p, &pl)) {
        if (ver != want || pl < 1) continue;
        for (int r = 0; r < p[0] && hdr + size * (r + 1) <= pl; r++) {
            const uint8_t *q = p + hdr + size * r;
            uint32_t v[4] = { 0 };
            int j;
            for (int k = 0; k < nc; k++)
                v[k] = rd32(q + c[k].off1) + (c[k].off2 >= 0 ? rd32(q + c[k].off2) : 0);
            for (j = 0; j < s->nl2 && !(s->l2_last[j].code == code && s->l2_last[j].rb == q[0]); j++) ;
            if (j < s->nl2) {
                for (int k = 0; k < nc; k++) {
                    uint32_t last = s->l2_last[j].v[k];
                    s->l2[c[k].idx] += v[k] >= last ? v[k] - last : v[k];  /* smaller: bearer re-established */
                }
            } else if (s->nl2 < 16)
                j = s->nl2++;
            else
                continue;
            s->l2_last[j].code = code;
            s->l2_last[j].rb = q[0];
            memcpy(s->l2_last[j].v, v, sizeof(v));
        }
        s->l2_valid = 1;
    }
}

/* rsrq < -29.99: not measured (raw 0, weak cell) */
static void stats_add_nb(stats_t *s, unsigned earfcn, int pci, double rsrp, double rsrq)
{
    int j;
    for (j = 0; j < s->nnb && !(s->nb[j].pci == pci && s->nb[j].earfcn == earfcn); j++) ;
    if (j == s->nnb) {
        if (s->nnb == 16) return;
        s->nb[j].earfcn = earfcn;
        s->nb[s->nnb++].pci = pci;
    }
    acc(&s->nb[j].rsrp, rsrp);
    if (rsrq > -29.99) acc(&s->nb[j].rsrq, rsrq);
}

/* 0xB179 v4: intra-frequency neighbours (L3 filtered, the values handover events are evaluated on) */
static void stats_ncell(stats_t *s, const uint8_t *b, int len)
{
    if (len < 28 || b[0] != 4) return;
    unsigned earfcn = rd32(b + 8);
    int spci = rd16(b + 12) & 0x1ff;
    s->have_srv_cell = 1;
    s->srv_earfcn = earfcn;
    s->srv_pci = spci;
    acc(&s->nb_srv, (int16_t)rd16(b + 16) / 16.0 - 180);
    for (int i = 0; i < b[24] && 28 + 12 * (i + 1) <= len; i++) {
        const uint8_t *r = b + 28 + 12 * i;
        int pci = rd16(r) & 0x1ff;
        if (pci != spci)
            stats_add_nb(s, earfcn, pci, (int16_t)rd16(r + 2) / 16.0 - 180, (rd16(r + 6) & 0xfff) / 16.0 - 30);
    }
}

/* 0xB195 subpacket 31 v3/v4: neighbours on every measured frequency (incl. inter-frequency during gaps) */
static void stats_conn_nb(stats_t *s, const uint8_t *b, int len)
{
    int ver, pl;
    const uint8_t *p;
    if (len < 4 || b[0] != 1) return;
    unsigned se = s->have_srv_cell ? s->srv_earfcn : s->earfcn;
    int sp = s->have_srv_cell ? s->srv_pci : s->pci, have = s->have_srv_cell || s->rf_valid;
    subpkt_it it = { b, len, 0, 4 };
    while (subpkt_next(&it, &ver, &p, &pl)) {
        int sid = p[-4];
        if (sid != 31 || (ver != 3 && ver != 4) || pl < 8) continue;
        unsigned earfcn = ver == 4 ? rd32(p) : rd16(p);
        int nc = rd16(p + (ver == 4 ? 4 : 2)) & 63, q = ver == 4 ? 8 : 4;
        for (int i = 0; i < nc && q + 52 * (i + 1) <= pl; i++) {
            const uint8_t *c = p + q + 52 * i;
            int pci = rd32(c) & 1023;
            if (have && earfcn == se && pci == sp) continue;
            stats_add_nb(s, earfcn, pci, (rd16(c + 12) & 4095) / 16.0 - 180, (rd32(c + 20) >> 10 & 1023) / 16.0 - 30);
        }
    }
}

static void stats_rlm(stats_t *s, const uint8_t *b, int len)
{
    if (len < 4 || b[0] != 1) return;
    for (int i = 0; i < b[3] && 4 + 12 * (i + 1) <= len; i++) {
        const uint8_t *r = b + 4 + 12 * i;
        acc(&s->rlm_oos, rd16(r + 2));
        s->t310 |= r[8] & 1;
    }
}

/* strongest neighbour cell index in s->nb, -1 if none */
__attribute__((unused)) static int stats_best_nb(const stats_t *s)
{
    int b = -1;
    for (int j = 0; j < s->nnb; j++)
        if (s->nb[j].rsrp.n && (b < 0 || mean(&s->nb[j].rsrp) > mean(&s->nb[b].rsrp))) b = j;
    return b;
}

/* UL queue samples: exact buffer (0xB066) if logged, else the BSR the modem reports to the eNB */
static const acc_t *stats_queue(const stats_t *s) { return s->ul_buf.n ? &s->ul_buf : &s->bsr; }

/* uplink queue delay in ms (mean and max queued bytes / uplink rate); returns 0 if nothing was reported */
#define QDELAY_WARN 50     /* ms: queue building up, UDP loss followed 1-2 s later in tests */
#define QBYTES_WARN 10000  /* and at least this much queued: on a near-idle link small bursts look like delay */
static int stats_qdelay(const stats_t *s, double el, double *mean_ms, double *max_ms)
{
    const acc_t *q = stats_queue(s);
    if (!q->n) return 0;
    double rate = s->ul_bytes / el;
    if (rate < 0.5e6 / 8) rate = 0.5e6 / 8;  /* floor 0.5 Mbit/s so an idle link doesn't divide by ~0 */
    *mean_ms = mean(q) / rate * 1000;
    *max_ms = q->max / rate * 1000;
    return 1;
}

/* standing uplink queue: the smallest queue of the interval in ms at the interval's uplink rate. A queue that never
 * empties means the link carries less than is sent; short spikes (video keyframes) leave it near 0. -1 if none. */
__attribute__((unused)) static double stats_qdelay_min(const stats_t *s, double el)
{
    const acc_t *q = stats_queue(s);
    if (!q->n) return -1;
    double rate = s->ul_bytes / el;
    if (rate < 0.5e6 / 8) rate = 0.5e6 / 8;
    return q->min / rate * 1000;
}

__attribute__((unused)) static int stats_queue_warn(const stats_t *s, double el)
{
    double qd, qm;
    return stats_qdelay(s, el, &qd, &qm) && qd >= QDELAY_WARN && mean(stats_queue(s)) >= QBYTES_WARN;
}

/* synchronous FDD HARQ: retransmission = PUSCH with no new MAC TB, 8 ms after a previous tx */

static long stats_ul_retx(const stats_t *s)
{
    long r = 0;
    for (size_t i = 0; i < s->ul_n; i++) {
        int t = s->ul_tx[i], p = (t + 10240 - 8) % 10240;
        if (t < 10240 && !(s->ul_new[t >> 3] >> (t & 7) & 1) && (s->ul_txmap[p >> 3] >> (p & 7) & 1))
            r++;
    }
    return r;
}

/* ---- trigger: the network's measurement rule (A1-A5 from meas_config) closest to firing, evaluated the way the modem
 * does: on the L3-filtered serving RSRP of 0xB179 (else the better antenna of 0xB193, smoothed) and the latest
 * neighbour measurements (0xB179 intra-frequency, 0xB195 incl. inter-frequency; a cell on another band is only
 * measured while the network has gaps on, so it is usually unknown until the search runs). Rules with the same
 * condition on several frequencies count as one (A5@1875/3500/6400). offsetFreq / cell offsets are not decoded (0).
 * gap: dB the signal can still move before the entering condition holds (<= 0: holds; A5 without a measured
 * neighbour: the serving part only, 0 once it holds). held: ms the whole condition has held, against the rule's time
 * to trigger. */
#define TRIG_MAX 32
#define TRIG_NB 32
typedef struct {
    char rep[112], name[48];   /* "A5[serving<rsrp-115dBm&nb>rsrp-113dBm,hys1dB,ttt480ms]", "A5@1875/3500/6400" */
    int ev, q1, q2, ttt;       /* 1..5 = A1..A5; threshold quantity 0 RSRP / 1 RSRQ; time to trigger, ms */
    double t1, t2, off, hys;   /* thresholds, A3 offset, hysteresis */
    unsigned earfcn[8];        /* A3-A5 frequencies, 0 = the serving one ("@?") */
    int nf;
    double since;              /* modem time the whole condition started to hold, < 0 = not holding */
} trig_rule_t;

typedef struct {
    char rules[700];           /* rules text the parsed list is from */
    int nr;
    trig_rule_t r[TRIG_MAX];
    int have_srv, have_raw, srv_pci, raw_pci;
    unsigned srv_earfcn, raw_earfcn;
    double srv_t, srv_rsrp, raw_t, raw_rsrp, raw_rsrq, last_t;
    int fed;                   /* a measurement arrived in this output interval */
    int nnb;
    struct { unsigned earfcn; int pci; double t, rsrp, rsrq; } nb[TRIG_NB];
    /* last evaluation */
    int valid, known, have_nb, nb_q, ttt;
    char name[48];
    double gap, nb_val, held;
} trig_t;

/* next "rsrp<v>" / "rsrq<v>" threshold in s -> quantity, value; NULL if none */
static const char *trig_thr(const char *s, int *q, double *v)
{
    const char *p = strstr(s, "rsr");
    char *e;
    if (!p || (p[3] != 'p' && p[3] != 'q')) return NULL;
    *q = p[3] == 'q';
    *v = strtod(p + 4, &e);
    return e;
}

static void trig_add(trig_t *t, const char *rep, int rl, const char *obj, int ol)
{
    char rs[112], os[24];
    trig_rule_t *r = NULL;
    if (rl < 4 || rep[0] != 'A' || rep[1] < '1' || rep[1] > '5' || rep[2] != '[') return;
    snprintf(rs, sizeof(rs), "%.*s", rl, rep);
    snprintf(os, sizeof(os), "%.*s", ol, obj);
    for (int i = 0; i < t->nr; i++)
        if (!strcmp(t->r[i].rep, rs)) r = &t->r[i];
    if (!r) {
        if (t->nr == TRIG_MAX) return;
        r = &t->r[t->nr];
        memset(r, 0, sizeof(*r));
        snprintf(r->rep, sizeof(r->rep), "%s", rs);
        r->ev = rs[1] - '0';
        r->since = -1;
        const char *x = rs + 3, *h = strstr(rs, ",hys"), *tt = strstr(rs, ",ttt");
        if (r->ev == 3) {
            const char *sv = strstr(rs, "serving");
            if (!sv) return;
            r->off = strtod(sv + 7, NULL);
        } else if (!(x = trig_thr(x, &r->q1, &r->t1)) || (r->ev == 5 && !trig_thr(x, &r->q2, &r->t2)))
            return;
        if (!h || !tt) return;
        r->hys = strtod(h + 4, NULL);
        r->ttt = atoi(tt + 4);
        snprintf(r->name, sizeof(r->name), "A%d", r->ev);
        t->nr++;
    }
    if (r->ev >= 3 && r->nf < 8 && (os[0] == '?' || (os[0] >= '0' && os[0] <= '9'))) {
        size_t l = strlen(r->name);
        r->earfcn[r->nf++] = os[0] == '?' ? 0 : (unsigned)strtoul(os, NULL, 10);
        snprintf(r->name + l, sizeof(r->name) - l, "%s%s", r->nf == 1 ? "@" : "/", os);
    }
}

/* rules text as in the meas_config event: "measId:report@object,..." (a report holds commas inside [...]) */
static void trig_parse(trig_t *t, const char *rules)
{
    const char *p = rules;
    snprintf(t->rules, sizeof(t->rules), "%s", rules);
    t->nr = 0;
    while (*p) {
        const char *c = strchr(p, ':'), *at;
        int depth = 0;
        if (!c) break;
        for (at = c + 1; *at && (depth || *at != '@'); at++)
            depth += *at == '[' ? 1 : *at == ']' ? -1 : 0;
        if (!*at) break;
        const char *obj = at + 1, *end = obj + strcspn(obj, ",");
        trig_add(t, c + 1, (int)(at - c - 1), obj, (int)(end - obj));
        p = *end ? end + 1 : end;
    }
}

static void trig_nb_set(trig_t *t, double mts, unsigned earfcn, int pci, double rsrp, double rsrq)
{
    int j;
    for (j = 0; j < t->nnb && !(t->nb[j].earfcn == earfcn && t->nb[j].pci == pci); j++) ;
    if (j == t->nnb) {
        if (t->nnb == TRIG_NB) {  /* full: replace the oldest */
            j = 0;
            for (int k = 1; k < t->nnb; k++)
                if (t->nb[k].t < t->nb[j].t) j = k;
        } else
            t->nnb++;
        t->nb[j].earfcn = earfcn;
        t->nb[j].pci = pci;
    }
    t->nb[j].t = mts;
    t->nb[j].rsrp = rsrp;
    t->nb[j].rsrq = rsrq;
}

/* latest measurements (offsets as in stats_ncell / stats_conn_nb / stats_meas); 1 if the packet was one of them */
__attribute__((unused)) static int trig_feed(trig_t *t, int code, double mts, const uint8_t *b, int len)
{
    if (code == LOG_NCELL) {
        if (len < 28 || b[0] != 4) return 0;
        t->have_srv = 1;
        t->srv_t = mts;
        t->srv_earfcn = rd32(b + 8);
        t->srv_pci = rd16(b + 12) & 0x1ff;
        t->srv_rsrp = (int16_t)rd16(b + 16) / 16.0 - 180;
        for (int i = 0; i < b[24] && 28 + 12 * (i + 1) <= len; i++) {
            const uint8_t *r = b + 28 + 12 * i;
            int pci = rd16(r) & 0x1ff;
            if (pci != t->srv_pci)
                trig_nb_set(t, mts, t->srv_earfcn, pci, (int16_t)rd16(r + 2) / 16.0 - 180, (rd16(r + 6) & 0xfff) / 16.0 - 30);
        }
    } else if (code == LOG_CONN_NB) {
        int ver, pl;
        const uint8_t *p;
        if (len < 4 || b[0] != 1) return 0;
        subpkt_it it = { b, len, 0, 4 };
        while (subpkt_next(&it, &ver, &p, &pl)) {
            if (p[-4] != 31 || (ver != 3 && ver != 4) || pl < 8) continue;
            unsigned earfcn = ver == 4 ? rd32(p) : rd16(p);
            int nc = rd16(p + (ver == 4 ? 4 : 2)) & 63, q = ver == 4 ? 8 : 4;
            for (int i = 0; i < nc && q + 52 * (i + 1) <= pl; i++) {
                const uint8_t *c = p + q + 52 * i;
                int pci = rd32(c) & 1023;
                if (!(t->have_srv && earfcn == t->srv_earfcn && pci == t->srv_pci))
                    trig_nb_set(t, mts, earfcn, pci, (rd16(c + 12) & 4095) / 16.0 - 180, (rd32(c + 20) >> 10 & 1023) / 16.0 - 30);
            }
        }
    } else if (code == LOG_MEAS) {
        if (len < 8 + 84 || b[4] != 0x19) return 0;
        double r0 = (rd32(b + 32) & 0xfff) / 16.0 - 180, r1 = (rd32(b + 36) & 0xfff) / 16.0 - 180;
        double rp = r0 > r1 ? r0 : r1, rq = (rd32(b + 44) >> 20 & 0x3ff) / 16.0 - 30;
        unsigned e = rd32(b + 8);
        int pci = rd32(b + 12) & 0x1ff, fresh = t->have_raw && mts - t->raw_t < 1 && e == t->raw_earfcn && pci == t->raw_pci;
        /* single samples are noisy: smooth over ~20 (about the modem's L3 filter at 50 samples/s) */
        t->raw_rsrp = fresh ? t->raw_rsrp + (rp - t->raw_rsrp) / 20 : rp;
        t->raw_rsrq = fresh ? t->raw_rsrq + (rq - t->raw_rsrq) / 20 : rq;
        t->have_raw = 1;
        t->raw_t = mts;
        t->raw_earfcn = e;
        t->raw_pci = pci;
    } else
        return 0;
    t->last_t = mts;
    t->fed = 1;
    return 1;
}

/* evaluate at modem time mts against the current rules text (the mobility's, NULL = not connected) */
__attribute__((unused)) static void trig_eval(trig_t *t, const char *rules, double mts)
{
    t->valid = 0;
    if (!rules) rules = "none";
    if (strcmp(rules, t->rules)) trig_parse(t, rules);  /* new rules: their time to trigger starts again */
    int fs = t->have_srv && mts - t->srv_t < 1, fr = t->have_raw && mts - t->raw_t < 1;
    double ms[2] = { fs ? t->srv_rsrp : t->raw_rsrp, t->raw_rsrq };
    unsigned se = fs ? t->srv_earfcn : t->raw_earfcn;
    int sp = fs ? t->srv_pci : t->raw_pci;
    for (int i = 0; i < t->nr; i++) {
        trig_rule_t *r = &t->r[i];
        int qn = r->ev == 5 ? r->q2 : r->q1, hn = 0, known = 1;  /* qn: neighbour quantity (A3: RSRP) */
        double mn = 0, g;
        if ((!fs && !fr) || (r->ev != 3 && r->ev != 4 && r->q1 && !fr)) { r->since = -1; continue; }
        if (r->ev >= 3)  /* strongest fresh neighbour on the rule's frequencies */
            for (int j = 0; j < t->nnb; j++) {
                double v = qn ? t->nb[j].rsrq : t->nb[j].rsrp;
                int on = 0;
                if (mts - t->nb[j].t > 2 || (t->nb[j].earfcn == se && t->nb[j].pci == sp) || (qn && v < -29.99)) continue;
                for (int k = 0; k < r->nf; k++)
                    on |= (r->earfcn[k] ? r->earfcn[k] : se) == t->nb[j].earfcn;
                if (on && (!hn || v > mn)) { mn = v; hn = 1; }
            }
        if (r->ev == 1) g = r->t1 + r->hys - ms[r->q1];
        else if (r->ev == 2) g = ms[r->q1] - (r->t1 - r->hys);
        else if (r->ev == 3 && hn) g = ms[0] + r->off + r->hys - mn;
        else if (r->ev == 4 && hn) g = r->t1 + r->hys - mn;
        else if (r->ev == 5) {
            g = ms[r->q1] - (r->t1 - r->hys);
            if (hn && r->t2 + r->hys - mn > g) g = r->t2 + r->hys - mn;
            else if (!hn && g < 0) g = 0;  /* serving side holds, the neighbour is not measured yet */
            known = hn;
        } else { r->since = -1; continue; }  /* A3 / A4 without a measured neighbour */
        int holds = known && g <= 0;
        if (!holds) r->since = -1;
        else if (r->since < 0) r->since = mts;
        /* closest to firing; on a tie the rule whose neighbour is measured */
        if (!t->valid || g < t->gap - 0.05 || (g < t->gap + 0.05 && known && !t->known)) {
            t->valid = 1;
            t->known = known;
            t->gap = g;
            t->have_nb = hn;
            t->nb_val = mn;
            t->nb_q = qn;
            t->ttt = r->ttt;
            t->held = holds ? (mts - r->since) * 1000 : 0;
            snprintf(t->name, sizeof(t->name), "%s", r->name);
        }
    }
}

/* end of an output interval: evaluate once more (the rules may have changed since); nothing measured in it: NA */
__attribute__((unused)) static void trig_interval(trig_t *t, const char *rules)
{
    trig_eval(t, rules, t->last_t);
    if (!t->fed) t->valid = 0;
    t->fed = 0;
}

static int stats_dispatch(stats_t *s, int code, const uint8_t *b, int len)
{
    switch (code) {
    case LOG_PDSCH: stats_pdsch(s, b, len); return 1;
    case LOG_PUSCH: stats_pusch(s, b, len); return 1;
    case LOG_MAC_UL: stats_mac_ul(s, b, len); return 1;
    case LOG_CSI: stats_csi(s, b, len); return 1;
    case LOG_MEAS: stats_meas(s, b, len); return 1;
    case LOG_UL_BUF: stats_ul_buf(s, b, len); return 1;
    case LOG_UL_TXST: stats_ul_txst(s, b, len); return 1;
    case LOG_PHICH: stats_phich(s, b, len); return 1;
    case LOG_PUSCH_PC: stats_pusch_pc(s, b, len); return 1;
    case LOG_RLC_DL: case LOG_RLC_UL: case LOG_PDCP_UL: stats_l2(s, code, b, len); return 1;
    case LOG_NCELL: stats_ncell(s, b, len); return 1;
    case LOG_RLM: stats_rlm(s, b, len); return 1;
    case LOG_CONN_NB: stats_conn_nb(s, b, len); return 1;
    }
    return 0;
}

__attribute__((unused)) static const char *MODS[4] = { "?", "QPSK", "16QAM", "64QAM" };

#endif
