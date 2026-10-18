/* Shared code for modem_link / lte_info: Qualcomm DIAG transport, AT commands and
 * PHY/MAC log parsers for SIM7600 (MDM9x07). Plain C99 + POSIX, no dependencies. */
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
static double now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
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

/* ------------------------------------------------------------------ PHY/MAC log parsers */
#define LOG_PDSCH  0xB173  /* LTE PHY PDSCH stat indication v5 */
#define LOG_PUSCH  0xB139  /* LTE LL1 PUSCH tx report v25 */
#define LOG_MAC_UL 0xB064  /* LTE MAC UL transport block */
#define LOG_CSI    0xB14D  /* LTE PHY PUCCH CSI report v24 */
#define LOG_MEAS   0xB193  /* LTE ML1 serving cell meas response */

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
} stats_t;

__attribute__((unused)) static void stats_reset(stats_t *s)
{
    uint16_t *tx = s->ul_tx;
    size_t cap = s->ul_cap;
    __typeof__(s->harq) h;
    memcpy(h, s->harq, sizeof(h));
    memset(s, 0, sizeof(*s));
    memcpy(s->harq, h, sizeof(h));
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

/* synchronous FDD HARQ: retransmission = PUSCH with no new MAC TB, 8 ms after a previous tx */
/* uplink queue delay in ms (mean and max BSR / uplink rate); returns 0 if no BSR was reported */
#define QDELAY_WARN 50     /* ms: queue building up, UDP loss followed 1-2 s later in tests */
#define QBYTES_WARN 10000  /* and at least this much queued: on a near-idle link small bursts look like delay */
static int stats_qdelay(const stats_t *s, double el, double *mean_ms, double *max_ms)
{
    if (!s->bsr.n) return 0;
    double rate = s->ul_bytes / el;
    if (rate < 0.5e6 / 8) rate = 0.5e6 / 8;  /* floor 0.5 Mbit/s so an idle link doesn't divide by ~0 */
    *mean_ms = mean(&s->bsr) / rate * 1000;
    *max_ms = s->bsr.max / rate * 1000;
    return 1;
}

__attribute__((unused)) static int stats_queue_warn(const stats_t *s, double el)
{
    double qd, qm;
    return stats_qdelay(s, el, &qd, &qm) && qd >= QDELAY_WARN && mean(&s->bsr) >= QBYTES_WARN;
}

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

static int stats_dispatch(stats_t *s, int code, const uint8_t *b, int len)
{
    switch (code) {
    case LOG_PDSCH: stats_pdsch(s, b, len); return 1;
    case LOG_PUSCH: stats_pusch(s, b, len); return 1;
    case LOG_MAC_UL: stats_mac_ul(s, b, len); return 1;
    case LOG_CSI: stats_csi(s, b, len); return 1;
    case LOG_MEAS: stats_meas(s, b, len); return 1;
    }
    return 0;
}

__attribute__((unused)) static const char *MODS[4] = { "?", "QPSK", "16QAM", "64QAM" };

#endif
