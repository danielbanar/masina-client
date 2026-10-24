/* Adaptive video bitrate over LTE, driven by the uplink queue that modem_link measures on the modem.
 *
 * modem_link sends each of its key=value lines to 127.0.0.1:2225 as well (the DIAG port can only have one reader).
 * modem_alink takes the uplink queue (ul_buf: exact bytes waiting in the modem, or bsr where the modem does not log
 * it), qdelay (queue / uplink rate) and ul_rate from them and sets the encoder bitrate over the camera's HTTP API
 * (/api/v1/set?video0.bitrate=<kbit/s>). It decides on every stats line, so it reacts as fast as modem_link's interval
 * (0.25 s in S92modemlink).
 *
 * How hard it reacts, and the highest bitrate it uses, come from a preset (table below):
 *   congested -> aim for a share of what the uplink carried, minus enough to empty the queue within `drain`
 *                seconds; while the bitrate is above that, cut to it (at least to down_factor of the bitrate, at most
 *                to cut_floor of it in one line). Once below it, hold: the queue is draining. Going by the rate rather
 *                than by whether the queue shrinks also works when only bsr is there, which tops out at 150 KB.
 *   clear     -> once clear for a while, go straight back to ul_share of what the uplink carried while congested
 *                (if that was in the last 10 s), then raise a small step per line (at least 25 kbit/s), up to the
 *                preset's max. After 10 s without congestion the link may carry more: at least 1 % of the max per
 *                line. Nothing queued counts as clear.
 *   otherwise -> hold.
 * Below 1 Mbit/s the frame rate goes down as well (/api/v1/set?video0.fps=): 40, 30, then 20 fps, so each frame keeps
 * about the bits it had at 1 Mbit/s and 60 fps. It also lowers the real floor: at 60 fps the encoder sends ~150 kbit/s
 * however low the bitrate is set.
 *
 * While enabled it owns the bitrate: a change from someone else (e.g. the ground station's bitrate slider) is where it
 * carries on from. The bitrate and frame rate the camera had when modem_alink took over, or the last change from
 * someone else, are restored when it is disabled or stops. No stats for 3 s: the bitrate is held.
 *
 * Control on port 2226 (all interfaces), HTTP or UDP: enable=0|1 and preset=performance|balanced|quality, keys
 * optionally prefixed "alink.". Both answer with a status line (ALINK;...;enabled=1;preset=...;bitrate=...).
 *   curl 'http://<drone>:2226/?preset=performance&enable=1'       any path; no query = status only
 *   echo 'preset=quality;enable=1' | nc -u -w1 <drone> 2226
 *
 * /etc/masina.conf: ALINK_ENABLED=true|false (default true), ALINK_PRESET (default balanced), ALINK_CAMERA=host[:port]
 * (default 127.0.0.1:80), ALINK_MIN_BITRATE=<kbit/s> (default 1), ALINK_CONTROL_PORT (default 2226), GROUND_IP: every
 * change is sent there on port 2224 as "ALINK;time=...;enabled=...;preset=...;bitrate=...;...;reason=...".
 *
 * usage: modem_alink [performance|balanced|quality]      SIGINT/SIGTERM gives the camera back and exits
 */
#define _GNU_SOURCE
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define MASINA_CONF "/etc/masina.conf"
#define GROUND_PORT "2224"
#define ALINK_PORT 2225 /* modem_link's lines arrive here on 127.0.0.1 */

#define MIN_GAP 0.2       /* s between changes: one per modem_link line at its 0.25 s interval, with some jitter */
#define UP_MIN_STEP 25    /* kbit/s: smallest raise per step */
#define CAP_VALID 10.0    /* s: how long the uplink rate seen while congested counts as what the link carries */
#define PROBE_STEP 0.01   /* of the preset's max per line, after CAP_VALID without congestion */
#define FPS_DEFAULT 60    /* if the camera does not say */
#define FPS_RETRY 10.0    /* s before trying again after the camera refused a frame rate */
#define GET_EVERY 3.0     /* s between camera polls */
#define STATS_TIMEOUT 3.0 /* s without stats before reporting no_data */
#define HTTP_TIMEOUT 1    /* s */

/* ---- presets */
typedef struct {
    const char *name;
    long max_bitrate;                  /* kbit/s */
    double qdelay_high, qbytes_min;    /* congested: qdelay >= qdelay_high ms with >= qbytes_min KB queued ... */
    double qbytes_high;                /* ... or >= qbytes_high KB queued whatever the delay (0 = off) */
    double ul_share, drain;            /* aim: ul_share of the uplink rate, minus the queue over drain s ... */
    double down_factor, cut_floor;     /* ... cutting to between cut_floor and down_factor of the bitrate per line
                                        * (the floor because one stalled interval reads as ~0 uplink) */
    double qdelay_clear, qbytes_clear; /* clear: qdelay < qdelay_clear ms, or < qbytes_clear KB queued */
    double up_after, up_step;          /* raise after up_after s clear, by up_step of the bitrate per line */
} preset_t;

/* the small qbytes_min keeps a near-idle link from looking congested: modem_link floors the rate at 0.5 Mbit/s,
 * so a 3 KB burst alone already reads as 50 ms */
static const preset_t PRESETS[] = {
    /*               max     congested       aim          cut           clear     raise */
    { "performance", 4000,   50, 5, 50,      0.70, 0.5,   0.70, 0.25,   20, 5,    3.0, 0.0075 }, /* ~3 %/s */
    { "balanced",    8000,   50, 10, 100,    0.80, 1.0,   0.85, 0.50,   25, 5,    2.0, 0.0125 }, /* ~5 %/s */
    { "quality",     16000,  100, 20, 0,     0.90, 2.0,   0.90, 0.50,   40, 10,   1.0, 0.02 },   /* ~8 %/s */
};

/* below `below` kbit/s use `fps`; back up only at 20 % above the step, so the frame rate does not flap */
static const struct {
    long below;
    int fps;
} FPS_STEPS[] = { { 1000, 40 }, { 667, 30 }, { 500, 20 } };

static volatile sig_atomic_t stop;
static void on_sig(int s) { (void)s; stop = 1; }

static double now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

/* 1/on/true/yes, 0/off/false/no, else -1 */
static int truthy(const char *v)
{
    if (!strcmp(v, "1") || !strcasecmp(v, "on") || !strcasecmp(v, "true") || !strcasecmp(v, "yes"))
        return 1;
    if (!strcmp(v, "0") || !strcasecmp(v, "off") || !strcasecmp(v, "false") || !strcasecmp(v, "no"))
        return 0;
    return -1;
}

static const preset_t *preset_find(const char *name)
{
    for (size_t i = 0; i < sizeof(PRESETS) / sizeof(PRESETS[0]); i++)
        if (!strcmp(PRESETS[i].name, name))
            return &PRESETS[i];
    return NULL;
}

/* ---- config */
typedef struct {
    char ground_ip[128];
    char camera_host[128];
    char camera_port[8];
    char preset[32];
    int enabled, control_port;
    long min_bitrate; /* kbit/s */
} conf_t;

/* the last occurrence of a key wins, as in Config::readConfig */
static void conf_read(conf_t *c)
{
    char camera[128] = "127.0.0.1:80", on[16];
    snprintf(c->preset, sizeof(c->preset), "balanced");
    c->enabled = 1;
    c->control_port = 2226;
    c->min_bitrate = 1;
    FILE *f = fopen(MASINA_CONF, "r");
    if (f) {
        char buf[256];
        while (fgets(buf, sizeof(buf), f)) {
            sscanf(buf, "GROUND_IP=%127s", c->ground_ip);
            sscanf(buf, "ALINK_CAMERA=%127s", camera);
            sscanf(buf, "ALINK_PRESET=%31s", c->preset);
            sscanf(buf, "ALINK_MIN_BITRATE=%ld", &c->min_bitrate);
            sscanf(buf, "ALINK_CONTROL_PORT=%d", &c->control_port);
            if (sscanf(buf, "ALINK_ENABLED=%15s", on) == 1 && truthy(on) >= 0)
                c->enabled = truthy(on);
        }
        fclose(f);
    } else
        fprintf(stderr, "warning: %s not found, using defaults\n", MASINA_CONF);
    char *colon = strrchr(camera, ':');
    snprintf(c->camera_port, sizeof(c->camera_port), "%s", colon ? colon + 1 : "80");
    if (colon) *colon = '\0';
    snprintf(c->camera_host, sizeof(c->camera_host), "%s", camera);
}

/* ---- camera HTTP API */

/* HTTP/1.0 GET on the camera; returns the status code with the body in body, or -1 if it did not answer */
static int http_get(const conf_t *c, const char *path, char *body, size_t size)
{
    struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_STREAM }, *res;
    if (getaddrinfo(c->camera_host, c->camera_port, &hints, &res) != 0)
        return -1;
    int fd = socket(res->ai_family, res->ai_socktype | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        freeaddrinfo(res);
        return -1;
    }
    /* the send timeout also bounds connect() on Linux */
    struct timeval tv = { .tv_sec = HTTP_TIMEOUT };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    int ok = connect(fd, res->ai_addr, res->ai_addrlen) == 0;
    freeaddrinfo(res);

    char buf[2048];
    size_t n = 0;
    if (ok) {
        int len = snprintf(buf, sizeof(buf), "GET %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n", path, c->camera_host);
        ok = send(fd, buf, len, MSG_NOSIGNAL) == len;
    }
    while (ok && n < sizeof(buf) - 1) {
        ssize_t r = recv(fd, buf + n, sizeof(buf) - 1 - n, 0);
        if (r <= 0)
            break; /* closed by the camera, or timed out */
        n += r;
    }
    close(fd);
    if (n == 0)
        return -1;
    buf[n] = '\0';
    int code;
    if (sscanf(buf, "HTTP/%*s %d", &code) != 1)
        return -1;
    const char *b = strstr(buf, "\r\n\r\n");
    snprintf(body, size, "%s", b ? b + 4 : "");
    return code;
}

/* a camera setting such as video0.bitrate (kbit/s) or video0.fps, or -1. The body may be JSON ({"video0.fps":60},
 * {"video0":{"fps":60}}) or a bare number, so take the first number after the key's last part, else the first one */
static long camera_get(const conf_t *c, const char *key)
{
    char path[64], body[512];
    snprintf(path, sizeof(path), "/api/v1/get?%s", key);
    if (http_get(c, path, body, sizeof(body)) != 200)
        return -1;
    const char *leaf = strrchr(key, '.');
    leaf = leaf ? leaf + 1 : key;
    const char *p = strstr(body, leaf);
    p = p ? p + strlen(leaf) : body;
    p += strcspn(p, "0123456789");
    return *p ? strtol(p, NULL, 10) : -1;
}

static int camera_set(const conf_t *c, const char *key, long value)
{
    char path[80], body[512];
    snprintf(path, sizeof(path), "/api/v1/set?%s=%ld", key, value);
    return http_get(c, path, body, sizeof(body)) == 200;
}

/* ---- modem_link stats */
typedef struct {
    int has_qdelay, has_queue, has_ul;
    double qdelay, queue, ul_rate; /* ms, KB, Mbit/s */
} link_t;

/* number after ";key=" in a modem_link line; 0 if missing or NA */
static int kv_num(const char *line, const char *key, double *v)
{
    char pat[32];
    snprintf(pat, sizeof(pat), ";%s=", key);
    const char *p = strstr(line, pat);
    if (!p)
        return 0;
    p += strlen(pat);
    char *end;
    *v = strtod(p, &end);
    return end != p;
}

/* interval lines only: event lines (cell_change, summary) carry no queue stats */
static int link_parse(const char *line, link_t *l)
{
    if (strstr(line, ";event=") || !strstr(line, ";qdelay="))
        return 0;
    l->has_qdelay = kv_num(line, "qdelay", &l->qdelay);
    l->has_queue = kv_num(line, "ul_buf", &l->queue) || kv_num(line, "bsr", &l->queue); /* exact buffer if logged */
    l->has_ul = kv_num(line, "ul_rate", &l->ul_rate);
    return 1;
}

/* ---- state and reporting (stdout and, with GROUND_IP, the ground station) */
typedef struct {
    int enabled;
    const preset_t *p;
    long current;      /* kbit/s; 0 until the camera has answered */
    long manual;       /* kbit/s to give back: the camera's when modem_alink took over, or someone else's last change */
    int fps, fps_full; /* current frame rate, and the one to give back */
    int camera_ok;     /* -1 until the first poll, so the first failure is reported */
    int was_congested, stats_ok;
    double last_queue; /* KB on the previous stats line */
    double last_change, clear_since, last_stats, fps_retry;
    double cap, cap_time; /* kbit/s the uplink carried on the last congested line, and when */
} alink_t;

static int udp_fd = -1;
static struct sockaddr_storage udp_addr;
static socklen_t udp_addrlen;

static void udp_open(const char *host)
{
    if (!*host)
        return;
    struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_DGRAM }, *res;
    if (getaddrinfo(host, GROUND_PORT, &hints, &res) != 0) {
        fprintf(stderr, "warning: cannot resolve GROUND_IP %s, changes are not sent\n", host);
        return;
    }
    udp_fd = socket(res->ai_family, res->ai_socktype | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    memcpy(&udp_addr, res->ai_addr, res->ai_addrlen);
    udp_addrlen = res->ai_addrlen;
    freeaddrinfo(res);
}

static size_t status_core(const alink_t *a, char *o, size_t size)
{
    char tm[16];
    time_t wall = time(NULL);
    strftime(tm, sizeof(tm), "%H:%M:%S", localtime(&wall));
    return snprintf(o, size, "ALINK;time=%s;enabled=%d;preset=%s;bitrate=%ldkbps;max=%ldkbps;fps=%d", tm, a->enabled, a->p->name,
                    a->current, a->p->max_bitrate, a->fps);
}

static size_t num_or_na(char *o, size_t size, const char *key, int ok, double v, int prec, const char *unit)
{
    return ok ? snprintf(o, size, ";%s=%.*f%s", key, prec, v, unit) : snprintf(o, size, ";%s=NA", key);
}

static void report(const alink_t *a, const char *reason, long prev, const link_t *l)
{
    char line[400];
    size_t n = status_core(a, line, sizeof(line));
    n += snprintf(line + n, sizeof(line) - n, ";prev=%ldkbps;reason=%s", prev, reason);
    if (l) {
        n += num_or_na(line + n, sizeof(line) - n, "qdelay", l->has_qdelay, l->qdelay, 0, "ms");
        n += num_or_na(line + n, sizeof(line) - n, "queue", l->has_queue, l->queue, 1, "KB");
        n += num_or_na(line + n, sizeof(line) - n, "ul_rate", l->has_ul, l->ul_rate, 2, "Mbps");
    }
    puts(line);
    fflush(stdout);
    if (udp_fd >= 0 && n < sizeof(line) - 1) {
        line[n++] = '\n'; /* newline-terminated like the SSC and modem_link lines */
        sendto(udp_fd, line, n, 0, (struct sockaddr *)&udp_addr, udp_addrlen);
    }
}

/* ---- control */
static void camera_down(alink_t *a, const conf_t *c)
{
    if (a->camera_ok)
        fprintf(stderr, "camera %s:%s not answering\n", c->camera_host, c->camera_port);
    a->camera_ok = 0;
}

/* re-reads the bitrate; a value modem_alink did not set (e.g. from the bitrate slider) is where it carries on from
 * and what it gives back later, and then 1 is returned. Within 2 % it is the camera rounding what modem_alink set. */
static int camera_sync(alink_t *a, const conf_t *c)
{
    long b = camera_get(c, "video0.bitrate");
    if (b <= 0) {
        camera_down(a, c);
        return 0;
    }
    a->camera_ok = 1;
    if (labs(b - a->current) > a->current / 50) {
        long prev = a->current;
        a->current = a->manual = b;
        a->clear_since = -1;
        report(a, "external", prev, NULL);
        return 1;
    }
    a->current = b;
    return 0;
}

static long clamp(const alink_t *a, const conf_t *c, long target)
{
    long hi = a->p->max_bitrate;
    long lo = c->min_bitrate < hi ? c->min_bitrate : hi;
    if (target < lo) target = lo;
    if (target > hi) target = hi;
    return target;
}

/* below 1 Mbit/s fewer frames (FPS_STEPS), back to the full rate when the bitrate recovers */
static void fps_update(alink_t *a, const conf_t *c)
{
    int fps = a->fps_full;
    for (size_t i = 0; i < sizeof(FPS_STEPS) / sizeof(FPS_STEPS[0]); i++) {
        long below = FPS_STEPS[i].below;
        if (a->fps <= FPS_STEPS[i].fps)
            below = below * 6 / 5; /* already at or under this step: leave it only at 20 % above */
        if (a->current < below && FPS_STEPS[i].fps < fps)
            fps = FPS_STEPS[i].fps;
    }
    if (fps == a->fps || now() < a->fps_retry)
        return;
    if (!camera_set(c, "video0.fps", fps)) {
        fprintf(stderr, "camera %s:%s did not accept %d fps\n", c->camera_host, c->camera_port, fps);
        a->fps_retry = now() + FPS_RETRY;
        return;
    }
    a->fps = fps;
    report(a, "fps", a->current, NULL);
}

/* returns 1 if the bitrate changed */
static int apply(alink_t *a, const conf_t *c, long target, const char *reason, const link_t *l)
{
    if (clamp(a, c, target) == a->current)
        return 0;
    /* re-read first, so a bitrate someone else set since the last poll is not overwritten */
    if (camera_sync(a, c))
        return 0;
    target = clamp(a, c, target);
    if (target == a->current)
        return 0;
    if (!camera_set(c, "video0.bitrate", target)) {
        fprintf(stderr, "camera %s:%s did not accept bitrate %ld\n", c->camera_host, c->camera_port, target);
        return 0;
    }
    long prev = a->current;
    a->current = target;
    report(a, reason, prev, l);
    fps_update(a, c);
    return 1;
}

/* reads the camera: what it has now is what gets given back later. When enabled, the preset's max applies at once. */
static void camera_attach(alink_t *a, const conf_t *c, const char *reason)
{
    long b = camera_get(c, "video0.bitrate");
    if (b <= 0) {
        camera_down(a, c);
        return;
    }
    long f = camera_get(c, "video0.fps");
    a->camera_ok = 1;
    a->current = a->manual = b;
    a->fps = a->fps_full = f > 0 ? (int)f : FPS_DEFAULT;
    a->was_congested = 0;
    a->clear_since = -1;
    report(a, reason, b, NULL);
    if (a->enabled) {
        apply(a, c, a->current, "max", NULL);
        fps_update(a, c);
    }
}

/* gives the camera back what it had when modem_alink took over, or someone else's last change */
static void release(alink_t *a, const conf_t *c, const char *reason)
{
    if (!a->current)
        return;
    long prev = a->current;
    camera_sync(a, c); /* a change from someone else just now is what stays */
    if (a->current != a->manual && camera_set(c, "video0.bitrate", a->manual))
        a->current = a->manual;
    if (a->fps != a->fps_full && camera_set(c, "video0.fps", a->fps_full))
        a->fps = a->fps_full;
    report(a, reason, prev, NULL);
}

static void control(alink_t *a, const conf_t *c, const link_t *l, double t)
{
    const preset_t *p = a->p;
    int congested = l->has_queue && ((l->has_qdelay && l->qdelay >= p->qdelay_high && l->queue >= p->qbytes_min) ||
                                     (p->qbytes_high > 0 && l->queue >= p->qbytes_high));
    int clear = !l->has_queue || l->queue < p->qbytes_clear || (l->has_qdelay && l->qdelay < p->qdelay_clear);
    if (a->current > p->max_bitrate) {
        apply(a, c, p->max_bitrate, "max", l); /* someone else set more than the preset allows */
    } else if (congested) {
        a->clear_since = -1;
        double target = a->current * p->down_factor;
        int cut;
        if (l->has_ul) {
            a->cap = l->ul_rate * 1000; /* with a queue waiting, the modem sends all the link gives it */
            a->cap_time = t;
            double aim = a->cap * p->ul_share - l->queue * 8 / p->drain; /* kbit/s */
            cut = a->current > aim;
            if (aim < target)
                target = aim;
        } else
            cut = !a->was_congested || l->queue >= a->last_queue; /* no rate: cut again only while the queue grows */
        if (target < a->current * p->cut_floor)
            target = a->current * p->cut_floor;
        if (cut && t - a->last_change >= MIN_GAP && apply(a, c, (long)target, "congestion", l))
            a->last_change = t;
    } else if (clear) {
        if (a->clear_since < 0)
            a->clear_since = t;
        if (a->current < p->max_bitrate && t - a->clear_since >= p->up_after && t - a->last_change >= MIN_GAP) {
            long step = (long)(a->current * p->up_step);
            if (t - a->cap_time >= CAP_VALID && step < p->max_bitrate * PROBE_STEP)
                step = (long)(p->max_bitrate * PROBE_STEP);
            if (step < UP_MIN_STEP) step = UP_MIN_STEP;
            long target = a->current + step;
            if (t - a->cap_time < CAP_VALID && a->cap * p->ul_share > target)
                target = (long)(a->cap * p->ul_share); /* queue drained: back to what the link carried */
            if (apply(a, c, target, "recover", l))
                a->last_change = t;
        }
    } else
        a->clear_since = -1;
    a->was_congested = congested;
    a->last_queue = l->has_queue ? l->queue : 0;
    fps_update(a, c); /* also follows a bitrate someone else set */
}

/* ---- control port: HTTP or UDP, "enable=1&preset=quality" or "enable=1;preset=quality"; keys may be prefixed
 * "alink.", words without '=' (an "ALINK" prefix, "status") are ignored. Returns 0 if something was not understood. */
static int command(alink_t *a, const conf_t *c, char *q)
{
    int ok = 1;
    char *save, *tok;
    for (tok = strtok_r(q, "&; \r\n", &save); tok; tok = strtok_r(NULL, "&; \r\n", &save)) {
        char *v = strchr(tok, '=');
        if (!v)
            continue;
        *v++ = '\0';
        if (!strncmp(tok, "alink.", 6))
            tok += 6;
        if (!strcmp(tok, "enable") || !strcmp(tok, "enabled")) {
            int on = truthy(v);
            if (on < 0) {
                ok = 0;
            } else if (on && !a->enabled) {
                a->enabled = 1;
                camera_attach(a, c, "enable");
            } else if (!on && a->enabled) {
                a->enabled = 0;
                release(a, c, "disable");
            }
        } else if (!strcmp(tok, "preset")) {
            const preset_t *p = preset_find(v);
            if (!p) {
                ok = 0;
            } else if (p != a->p) {
                a->p = p;
                report(a, "preset", a->current, NULL);
                if (a->enabled && a->current > p->max_bitrate)
                    apply(a, c, p->max_bitrate, "max", NULL);
            }
        } else
            ok = 0;
    }
    return ok;
}

static size_t status_reply(const alink_t *a, int ok, char *o, size_t size)
{
    size_t n = status_core(a, o, size);
    n += snprintf(o + n, size - n, ";manual=%ldkbps%s\n", a->manual, ok ? "" : ";error=bad_command");
    return n < size ? n : size - 1;
}

static int ctl_tcp = -1, ctl_udp = -1;

static void control_open(int port)
{
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = htonl(INADDR_ANY) };
    int one = 1;
    ctl_tcp = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (ctl_tcp >= 0)
        setsockopt(ctl_tcp, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (ctl_tcp < 0 || bind(ctl_tcp, (struct sockaddr *)&addr, sizeof(addr)) < 0 || listen(ctl_tcp, 4) < 0) {
        perror("control port (HTTP)");
        if (ctl_tcp >= 0) close(ctl_tcp);
        ctl_tcp = -1;
    }
    ctl_udp = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (ctl_udp < 0 || bind(ctl_udp, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("control port (UDP)");
        if (ctl_udp >= 0) close(ctl_udp);
        ctl_udp = -1;
    }
}

/* one request per connection: "GET /anything?query HTTP/1.x" */
static void control_http(alink_t *a, const conf_t *c)
{
    int fd = accept4(ctl_tcp, NULL, NULL, SOCK_CLOEXEC);
    if (fd < 0)
        return;
    /* a client that connects and says nothing must not hold up the control loop for long */
    struct timeval tv = { .tv_usec = 500000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    char req[1024];
    ssize_t n = recv(fd, req, sizeof(req) - 1, 0);
    if (n > 0) {
        req[n] = '\0';
        req[strcspn(req, "\r\n")] = '\0'; /* request line only */
        char *q = strchr(req, '?'), *end;
        if (q && (end = strchr(q, ' ')))
            *end = '\0';
        int ok = !q || command(a, c, q + 1);
        char status[320], resp[512];
        status_reply(a, ok, status, sizeof(status));
        int len = snprintf(resp, sizeof(resp), "HTTP/1.0 %s\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n%s",
                           ok ? "200 OK" : "400 Bad Request", status);
        send(fd, resp, len, MSG_NOSIGNAL);
    }
    close(fd);
}

static void control_udp(alink_t *a, const conf_t *c)
{
    char buf[512], status[320];
    struct sockaddr_storage from;
    socklen_t fromlen = sizeof(from);
    ssize_t n;
    while ((n = recvfrom(ctl_udp, buf, sizeof(buf) - 1, MSG_DONTWAIT, (struct sockaddr *)&from, &fromlen)) > 0) {
        buf[n] = '\0';
        int ok = command(a, c, buf);
        size_t len = status_reply(a, ok, status, sizeof(status));
        sendto(ctl_udp, status, len, 0, (struct sockaddr *)&from, fromlen);
        fromlen = sizeof(from);
    }
}

int main(int argc, char **argv)
{
    static conf_t c;
    conf_read(&c);
    static alink_t a = { .camera_ok = -1, .stats_ok = 1, .last_change = -1e9, .clear_since = -1, .cap_time = -1e9 };
    const char *name = argc > 1 ? argv[1] : c.preset;
    if (!(a.p = preset_find(name))) {
        fprintf(stderr, "unknown preset %s (performance, balanced, quality), using balanced\n", name);
        a.p = preset_find("balanced");
    }
    a.enabled = c.enabled;
    udp_open(c.ground_ip);

    int in = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(ALINK_PORT), .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    if (in < 0 || bind(in, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind 127.0.0.1:2225");
        return 1;
    }
    control_open(c.control_port);
    struct sigaction sa = { .sa_handler = on_sig }; /* no SA_RESTART: select() returns EINTR */
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    double next_get = 0;
    a.last_stats = now();
    while (!stop) {
        fd_set rd;
        FD_ZERO(&rd);
        FD_SET(in, &rd);
        int maxfd = in;
        if (ctl_tcp >= 0) {
            FD_SET(ctl_tcp, &rd);
            if (ctl_tcp > maxfd) maxfd = ctl_tcp;
        }
        if (ctl_udp >= 0) {
            FD_SET(ctl_udp, &rd);
            if (ctl_udp > maxfd) maxfd = ctl_udp;
        }
        struct timeval tv = { .tv_usec = 250000 };
        int r = select(maxfd + 1, &rd, NULL, NULL, &tv);
        double t = now();
        if (t >= next_get) {
            if (!a.current)
                camera_attach(&a, &c, "start"); /* until the camera has answered once; it may start after us */
            else
                camera_sync(&a, &c);
            next_get = t + GET_EVERY;
        }
        if (r > 0 && FD_ISSET(in, &rd)) {
            /* only the newest line counts if several arrived while a camera request was in flight */
            char line[4096];
            ssize_t n;
            link_t l, latest = { 0 };
            int have = 0;
            while ((n = recv(in, line, sizeof(line) - 1, MSG_DONTWAIT)) > 0) {
                line[n] = '\0';
                if (link_parse(line, &l)) {
                    latest = l;
                    have = 1;
                }
            }
            if (have) {
                a.last_stats = t;
                a.stats_ok = 1;
                if (a.enabled && a.current)
                    control(&a, &c, &latest, t);
            }
        }
        if (r > 0 && ctl_tcp >= 0 && FD_ISSET(ctl_tcp, &rd))
            control_http(&a, &c);
        if (r > 0 && ctl_udp >= 0 && FD_ISSET(ctl_udp, &rd))
            control_udp(&a, &c);
        if (a.enabled && a.current && a.stats_ok && t - a.last_stats >= STATS_TIMEOUT) {
            a.stats_ok = 0;
            report(&a, "no_data", a.current, NULL); /* the bitrate stays where it is until stats come back */
        }
    }
    if (a.enabled)
        release(&a, &c, "exit");
    return 0;
}
