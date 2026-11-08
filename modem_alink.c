/* Adaptive video bitrate over LTE, driven by the uplink queue that modem_link measures on the modem.
 *
 * modem_link sends each of its key=value lines to 127.0.0.1:2225 as well (the DIAG port can only have one reader).
 * modem_alink takes the uplink queue (ul_buf: exact bytes waiting in the modem, or bsr where the modem does not log
 * it), qdelay (queue / uplink rate) and ul_rate from them and sets the encoder bitrate over the camera's HTTP API
 * (/api/v1/set?video0.bitrate=<kbit/s>). It decides on every stats line, so it reacts as fast as modem_link's interval
 * (0.25 s in S92modemlink).
 *
 * Congestion is a standing queue: qdelay_min / ul_buf_min, the smallest queue of the interval. A queue that never
 * empties means the link carries less than is sent. Video keyframes only make short spikes that drain within the
 * interval, so they leave it near 0 (with the interval average they read as congestion and cut the bitrate for
 * nothing: 16 % of the 0.25 s lines at 7 Mbit/s with 12x keyframes, against 0 for the standing queue). Lines without
 * qdelay_min (older modem_link) use the interval average as before.
 *
 * The link loop (control) sets the target from them, and only it does; how hard it reacts, and the highest target it
 * uses, come from a preset (table below):
 *   congested -> aim for a share of what the uplink carried, minus enough to empty the queue within `drain`
 *                seconds; while the bitrate is above that, cut to it (at least to down_factor of the bitrate, at most
 *                to cut_floor of it in one line). Once below it, hold: the queue is draining. Going by the rate rather
 *                than by whether the queue shrinks also works when only bsr is there, which tops out at 150 KB.
 *   clear     -> once clear for a while, go straight back to ul_share of what the uplink carried while congested
 *                (if that was in the last 10 s), then raise a small step per line (at least 25 kbit/s; a quarter
 *                step while still within those 10 s, it is where the link congested), up to the preset's max. After 10 s without congestion the link may carry more: at least 1 % of the max per
 *                line. Nothing queued counts as clear. Raised only while the output fills at least
 *                ALINK_PROBE_FILL of the target (default 0.8; 0 = whatever the output): a clear link says nothing
 *                about more than it is sent.
 *   otherwise -> hold.
 * The network's own rules (modem_link's trigger fields: the measurement rule closest to firing) say when the link is
 * about to change:
 *   edge      -> a rule within 2 dB of firing (A2 band search, A3/A5 handover, the last-resort A2 before a release;
 *                not A1, the signal getting better): no raising, the link it would probe is about to go. Cuts still
 *                happen, at the cell edge the uplink is short of transmit power.
 *   handover  -> for 1 s after the serving cell changes (a handover, or service back after a release) no cut: the
 *                queue the switch built drains on the new cell, which is usually the better one.
 *   no service-> no serving cell (radio link lost, released): no raising. The queue fields are NA then, which the
 *                interval-average fallback would read as clear.
 * Each is reported once when it starts (reason=edge / handover / no_service / service).
 *
 * Two loops. The link loop above only writes the target: what the link should carry. The overshoot loop only reads it
 * and keeps the measured output (transmit counters of the interface the stream leaves on, found from waybeam's
 * outgoing.server and the routing table, or ALINK_IFACE; minus IP/UDP/RTP headers; over FD_WINDOW s) at the target,
 * with the encoder bitrate (never above the target, never below ALINK_ENC_MIN, default 1000 kbit/s: waybeam does not
 * encode below that) and, with the encoder at its floor, the ladder: the frame rate to two thirds (60 -> 40), then the
 * ISP noise set (despike 15, sharpness 0, grayscale; the camera's own values are kept to put back), then the frame rate
 * one step lower at a time (30 20 15 12 10, not below ALINK_MIN_FPS). The performance preset starts the ladder already
 * once the encoder is at 2000 kbit/s (ALINK_LADDER_FROM overrides, 0 = only at the floor). A dark, high-gain or very
 * detailed scene can make the encoder send several times its bitrate; the ladder takes that back.
 *   down: the output at or above ALINK_BITRATE_OVERSHOOT_MAX x the target (default 1.5; while the link is congested
 *         anything above it, FD_OVER): the encoder bitrate by the overshoot, aiming the output at the target; at its
 *         floor one stage of the ladder per measurement; at the algorithm's jump x the target or more, the encoder
 *         straight to its floor and every stage expected to be needed at once.
 *   up:   the output below OS_BACK x the target for the algorithm's hold (or the preset's up_after), the link not
 *         struggling: the ladder back first, then the encoder bitrate up to where the output should fill the target
 *         (never above it), the algorithm's gap apart (doubled up to FD_UP_MAX after a step that had to be undone).
 * ALINK_BITRATE_OVERSHOOT_CONTROL=false: the encoder bitrate is the target, and the ladder only runs while the link is
 * congested with the target at the floor. Without modem stats the target stays where it was (at start: the bitrate
 * that was set).
 *
 * How the overshoot loop moves is switchable for comparing in flight (ALINK_ALGO, control port algo=<name|1..8>):
 * mid (default), fast, slow, coarse, gray_last, and fixed_mid, fixed_fast, fixed_slow which ignore the link (the target
 * stays at the bitrate that was set, no congestion cuts); see ALGOS.
 *
 * Thermal: the SoC temperature (/sys/devices/virtual/mstar/msys/TEMP_R) caps the frame rate by /etc/temp_profile.conf
 * ("<min>-<max> <fps|-> <scale of the full rate|-> <update s>", first matching line), back up THERM_HYST degrees below
 * the hotter band. This wins over everything and also works while disabled (replaces the thermal-throttle script).
 *
 * Image (ISP) settings: ALINK_ISP_DESPIKE (0..15), ALINK_ISP_SHARPNESS (0..255) and ALINK_ISP_GRAYSCALE are set on the
 * camera (/api/v1/iq/set: nr_despike, sharpness, color_to_gray) and kept there: every ISP_EVERY s they are read back
 * and set again if waybeam lost them (it reloads the sensor bin, and with it the ISP defaults, on every start and
 * reinit). Not set = left alone. A dark, high-gain scene is mostly noise; despike 15 + sharpness 0 halve its bitrate,
 * grayscale halves it again (measured on SSC338Q/IMX415). Works while disabled too.
 *
 * While enabled it owns the bitrate: a change from someone else (e.g. the ground station's bitrate slider) is the new
 * target, where it carries on from. The bitrate and frame rate the camera had when modem_alink took over, or the last change from
 * someone else, are restored when it is disabled or stops. No stats for 3 s: the bitrate is held.
 *
 * Control on port 2226 (all interfaces), HTTP or UDP: enable=0|1, preset=performance|balanced|quality,
 * bitrate_overshoot_control=0|1, bitrate_overshoot_max=<x>, algo=<name|1..8>, probe_fill=<0..1>, isp_despike=<0..15>, isp_sharpness=<0..255> and
 * isp_grayscale=0|1 (-1 = stop managing that one) (not kept: masina.conf sets them at start), keys
 * optionally prefixed "alink.". Both answer with a status line (ALINK;...;enabled=1;preset=...;bitrate=...).
 *   curl 'http://<drone>:2226/?preset=performance&enable=1'       any path; no query = status only
 *   echo 'preset=quality;enable=1' | nc -u -w1 <drone> 2226
 *
 * /etc/masina.conf: ALINK_ENABLED=true|false (default true), ALINK_PRESET (default balanced), ALINK_CAMERA=host[:port]
 * (default 127.0.0.1:80), ALINK_MIN_BITRATE=<kbit/s> (default 1), ALINK_CONTROL_PORT (default 2226),
 * ALINK_ENC_MIN=<kbit/s> (default 1000; waybeam clamps anything lower to 1000), ALINK_LADDER_FROM=<kbit/s> (default:
 * the preset's), ALINK_MIN_FPS (default 15), ALINK_IFACE=auto|<ifname> (default auto),
 * ALINK_THERMAL=true|false (default true), ALINK_TEMP_PROFILE=<path> (default /etc/temp_profile.conf),
 * ALINK_BITRATE_OVERSHOOT_CONTROL=true|false (default false), ALINK_BITRATE_OVERSHOOT_MAX=<x> (default 1.5),
 * ALINK_ALGO=<name|1..8> (default mid), ALINK_PROBE_FILL=<0..1> (default 0.8),
 * ALINK_ISP_DESPIKE=<0..15>, ALINK_ISP_SHARPNESS=<0..255>, ALINK_ISP_GRAYSCALE=true|false (default: not set), GROUND_IP: every
 * change is sent there on port 2224 as "ALINK;time=...;enabled=...;preset=...;bitrate=...;...;reason=...".
 *
 * usage: modem_alink [performance|balanced|quality]      SIGINT/SIGTERM gives the camera back and exits
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
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
#define EDGE_GAP 2.0      /* dB: a network rule this close to firing (search, handover, release): no raising */
#define HO_GRACE 1.0      /* s after a cell change without cuts: the queue the switch built drains on the new cell */
#define FD_SAMPLE 0.25    /* s between transmit-counter samples */
#define FD_WINDOW 1.0     /* s the output is averaged over (a 1 s GOP's keyframe) */
#define FD_SETTLE 0.25    /* s after a change before a window counts, on top of FD_WINDOW: going down is fast ... */
/* ... going back up slow: s between steps up (the algorithm's gap) ... */
#define FD_UP_MAX 60.0    /* ... doubled up to this after a step up that had to be undone (it would only bounce) ... */
#define FD_UP_CALM 20.0   /* ... and back to the gap after this long without a step down */
#define FD_OVER 1.05      /* at the floor, output above this share of the target means frames have to go */
#define FD_AIM 0.90       /* drop to the step expected to give this share of the target */
#define FD_HDR 40         /* bytes per packet that are not video: IPv4 20 + UDP 8 + RTP 12 (+14 on Ethernet) */
#define OS_BACK 0.8       /* overshoot loop: back up once the output is below this share of the target */
#define PROBE_FILL 0.8    /* link loop: the target is raised only while the output is at least this share of it
                           * (ALINK_PROBE_FILL, control port probe_fill; 0 = whatever the output) */
#define ISP_GAIN 2.0      /* the output is taken to drop by this with the ISP stage (measured ~4: despike + sharpness
                           * halve it, grayscale halves it again; the lower guess drops more frames, recovery adds back) */
#define FD_IFACE_EVERY 30.0 /* s between looking up the stream's route again */
#define THERM_TEMP "/sys/devices/virtual/mstar/msys/TEMP_R"
#define THERM_HYST 2      /* degrees below a band before going back up from it */
#define THERM_MAX 16      /* profile lines */
#define ISP_EVERY 3.0     /* s between checks that the camera still has the ISP settings */
#define ISP_N 3           /* managed ISP settings, see ISP_KEYS */
static const int ISP_FLOOR[ISP_N] = { 15, 0, 1 }; /* the floor's ISP stage: despike 15, sharpness 0, grayscale */

/* ALINK_ISP_* / isp_* (control port) -> /api/v1/iq name and the highest value */
static const struct { const char *ctl, *iq; int max; } ISP_KEYS[ISP_N] = {
    { "isp_despike", "nr_despike", 15 },
    { "isp_sharpness", "sharpness", 255 },
    { "isp_grayscale", "color_to_gray", 1 },
};

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
    double qmin_high, qmin_clear;      /* standing queue (qdelay_min, ms): congested at >= qmin_high with
                                        * >= qbytes_min KB still queued (or >= qbytes_high KB), clear below qmin_clear */
    long ladder_from;                  /* kbit/s: the floor's ladder (30 fps, ISP stage, lower fps) already starts at or
                                        * below this, alongside the bitrate cuts; 0 = only at the floor */
} preset_t;

/* the small qbytes_min keeps a near-idle link from looking congested: modem_link floors the rate at 0.5 Mbit/s,
 * so a 3 KB burst alone already reads as 50 ms */
static const preset_t PRESETS[] = {
    /*               max     congested       aim          cut           clear     raise            standing  ladder */
    { "performance", 4000,   50, 5, 50,      0.70, 0.5,   0.70, 0.25,   20, 5,    3.0, 0.0075,     10, 3,    2000 }, /* ~3 %/s */
    { "balanced",    8000,   50, 10, 100,    0.80, 1.0,   0.85, 0.50,   25, 5,    2.0, 0.0125,     20, 5,    0 },    /* ~5 %/s */
    { "quality",     16000,  100, 20, 0,     0.90, 2.0,   0.90, 0.50,   40, 10,   1.0, 0.02,       40, 10,   0 },    /* ~8 %/s */
};

/* ---- overshoot loop algorithms (ALINK_ALGO, control port algo=<name>): to compare in flight */
enum { UP_STEP, UP_COARSE, UP_ALL };
typedef struct {
    const char *name;
    int link;       /* 1: the link loop sets the target from the modem stats; 0: the target stays at the bitrate that
                     * was set (the link ignored: no congestion cuts, no probing; the overshoot loop runs even when
                     * ALINK_BITRATE_OVERSHOOT_CONTROL is off) */
    double jump;    /* output at or above this x the target: the encoder straight to its floor and every stage of the
                     * ladder expected to be needed, in one step; 0 = one step per measurement */
    double down;    /* s at least between steps down (on top of the 1.25 s measurement settle); 0 = every measurement */
    int up;         /* the ladder back: UP_STEP every frame-rate step (60 40 30 20 15 12 10), UP_COARSE 40 then full,
                     * UP_ALL frame rate and ISP stage back at once */
    double hold;    /* s the output has to stay below OS_BACK x the target before stepping up; 0 = the preset's up_after */
    double gap;     /* s between steps back up (doubled up to FD_UP_MAX after one that had to be undone) */
    int gray_last;  /* the ISP stage (grayscale) goes last, after the full frame rate; else at two thirds (40) */
    int fit;        /* UP_STEP: a stage skips the steps the output, scaled by the frame rate, still fits */
    double raise;   /* the encoder bitrate back up by at most this factor per step; 0 = straight to where the output
                     * should fill the target */
} algo_t;

static const algo_t ALGOS[] = {
    /* name          link jump down up         hold gap  gray fit raise */
    { "mid",         1,   2.0, 0,   UP_STEP,   0,   2.0, 0,   1,  0    }, /* stage by stage, all at once at 2x */
    { "fast",        1,   1.0, 0,   UP_ALL,    1.0, 1.0, 0,   0,  0    }, /* all down at once, all back 1 s after */
    { "slow",        1,   0,   3.0, UP_STEP,   8.0, 5.0, 0,   0,  1.25 }, /* a stage every 3 s; back after 8 s, 5 s apart */
    { "coarse",      1,   2.0, 0,   UP_COARSE, 0,   2.0, 0,   0,  0    }, /* back: 15 -> 40, color, 60 */
    { "gray_last",   1,   2.0, 0,   UP_STEP,   0,   1.5, 1,   1,  0    }, /* back: frames up in grayscale, color last */
    { "fixed_mid",   0,   2.0, 0,   UP_STEP,   0,   2.0, 0,   1,  0    }, /* as mid, fast, slow, the link ignored */
    { "fixed_fast",  0,   1.0, 0,   UP_ALL,    1.0, 1.0, 0,   0,  0    },
    { "fixed_slow",  0,   0,   3.0, UP_STEP,   8.0, 5.0, 0,   0,  1.25 },
};
#define ALGO_DEFAULT "mid"

static const algo_t *algo_find(const char *name)
{
    char *end;
    long i = strtol(name, &end, 10); /* by name or number (1..8) */
    if (end != name && !*end && i >= 1 && i <= (long)(sizeof(ALGOS) / sizeof(ALGOS[0])))
        return &ALGOS[i - 1];
    for (size_t k = 0; k < sizeof(ALGOS) / sizeof(ALGOS[0]); k++)
        if (!strcmp(ALGOS[k].name, name))
            return &ALGOS[k];
    return NULL;
}

/* frame-rate steps, highest first: even decimations of the full rate (60: 60 40 30 20 15 12 10) */
#define FD_NSTEPS 7
static int fd_step(int full, int i)
{
    static const int num[FD_NSTEPS] = { 1, 2, 1, 1, 1, 1, 1 }, den[FD_NSTEPS] = { 1, 3, 2, 3, 4, 5, 6 };
    return full * num[i] / den[i];
}

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
    long enc_min;     /* kbit/s: the encoder's own floor, the bitrate goes no lower */
    long ladder_from; /* ALINK_LADDER_FROM: kbit/s, -1 = the preset's */
    int min_fps, thermal;
    int os_control;   /* ALINK_BITRATE_OVERSHOOT_CONTROL */
    int isp[ISP_N];   /* ALINK_ISP_DESPIKE / _SHARPNESS / _GRAYSCALE, -1 = leave alone */
    double os_max;    /* ALINK_BITRATE_OVERSHOOT_MAX */
    double probe_fill; /* ALINK_PROBE_FILL */
    char iface[32];   /* "auto": the route to waybeam's outgoing.server */
    char algo[32];    /* ALINK_ALGO */
    char temp_profile[128];
} conf_t;

/* the last occurrence of a key wins, as in Config::readConfig */
static void conf_read(conf_t *c)
{
    char camera[128] = "127.0.0.1:80", on[16];
    snprintf(c->preset, sizeof(c->preset), "balanced");
    c->enabled = 1;
    c->control_port = 2226;
    c->min_bitrate = 1;
    c->enc_min = 1000;
    c->ladder_from = -1;
    c->min_fps = 15;
    c->thermal = 1;
    c->os_max = 1.5;
    c->probe_fill = PROBE_FILL;
    for (int i = 0; i < ISP_N; i++)
        c->isp[i] = -1;
    snprintf(c->iface, sizeof(c->iface), "auto");
    snprintf(c->algo, sizeof(c->algo), ALGO_DEFAULT);
    snprintf(c->temp_profile, sizeof(c->temp_profile), "/etc/temp_profile.conf");
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
            sscanf(buf, "ALINK_ENC_MIN=%ld", &c->enc_min);
            sscanf(buf, "ALINK_LADDER_FROM=%ld", &c->ladder_from);
            sscanf(buf, "ALINK_MIN_FPS=%d", &c->min_fps);
            sscanf(buf, "ALINK_IFACE=%31s", c->iface);
            sscanf(buf, "ALINK_ALGO=%31s", c->algo);
            if (sscanf(buf, "ALINK_THERMAL=%15s", on) == 1 && truthy(on) >= 0)
                c->thermal = truthy(on);
            sscanf(buf, "ALINK_TEMP_PROFILE=%127s", c->temp_profile);
            if (sscanf(buf, "ALINK_BITRATE_OVERSHOOT_CONTROL=%15s", on) == 1 && truthy(on) >= 0)
                c->os_control = truthy(on);
            sscanf(buf, "ALINK_BITRATE_OVERSHOOT_MAX=%lf", &c->os_max);
            sscanf(buf, "ALINK_PROBE_FILL=%lf", &c->probe_fill);
            sscanf(buf, "ALINK_ISP_DESPIKE=%d", &c->isp[0]);
            sscanf(buf, "ALINK_ISP_SHARPNESS=%d", &c->isp[1]);
            if (sscanf(buf, "ALINK_ISP_GRAYSCALE=%15s", on) == 1 && truthy(on) >= 0)
                c->isp[2] = truthy(on);
        }
        fclose(f);
    } else
        fprintf(stderr, "warning: %s not found, using defaults\n", MASINA_CONF);
    for (int i = 0; i < ISP_N; i++)
        if (c->isp[i] > ISP_KEYS[i].max)
            c->isp[i] = ISP_KEYS[i].max;
    if (c->os_max < 1.05)
        c->os_max = 1.05; /* the measurement is only good to a few % */
    if (c->probe_fill < 0) c->probe_fill = 0;
    if (c->probe_fill > 1) c->probe_fill = 1;
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

    char buf[8192]; /* /api/v1/iq is ~4 KB */
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

/* not written to the camera's flash where it has /api/v1/live/set, else camera_set */
static int camera_set_live(const conf_t *c, const char *key, long value)
{
    static int no_live;
    char path[80], body[512];
    if (!no_live) {
        snprintf(path, sizeof(path), "/api/v1/live/set?%s=%ld", key, value);
        int code = http_get(c, path, body, sizeof(body));
        if (code == 200)
            return 1;
        if (code != 404)
            return 0;
        no_live = 1; /* older camera API */
    }
    return camera_set(c, key, value);
}

/* "value" of a string setting (outgoing.server -> udp://10.0.0.20:2222); 0 if not there */
static int camera_get_str(const conf_t *c, const char *key, char *o, size_t size)
{
    char path[64], body[512];
    snprintf(path, sizeof(path), "/api/v1/get?%s", key);
    if (http_get(c, path, body, sizeof(body)) != 200)
        return 0;
    const char *p = strstr(body, "\"value\"");
    if (!p || !(p = strchr(p + 7, '"')))
        return 0;
    p++;
    int n = (int)strcspn(p, "\"");
    snprintf(o, size, "%.*s", n, p);
    return n > 0;
}

/* ---- modem_link stats */
typedef struct {
    int has_qdelay, has_queue, has_ul, has_standing, has_trigger, has_cell;
    double qdelay, queue, ul_rate; /* ms, KB, Mbit/s */
    double qdelay_min, queue_min;  /* standing queue: smallest of the interval, ms and KB */
    char trigger[48];              /* network rule closest to firing ("A2", "A5@1875/3500/6400") ... */
    double trigger_gap;            /* ... dB before its condition holds (<= 0: holds) */
    double earfcn, pci;            /* serving cell */
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

/* text after ";key=" up to the next ';'; 0 if missing or NA */
static int kv_str(const char *line, const char *key, char *o, size_t size)
{
    char pat[32];
    snprintf(pat, sizeof(pat), ";%s=", key);
    const char *p = strstr(line, pat);
    if (!p)
        return 0;
    p += strlen(pat);
    int n = (int)strcspn(p, ";\r\n");
    if (!n || (n == 2 && !strncmp(p, "NA", 2)))
        return 0;
    snprintf(o, size, "%.*s", n, p);
    return 1;
}

/* interval lines only: event lines (cell_change, summary) carry no queue stats */
static int link_parse(const char *line, link_t *l)
{
    if (strstr(line, ";event=") || !strstr(line, ";qdelay="))
        return 0;
    l->has_qdelay = kv_num(line, "qdelay", &l->qdelay);
    l->has_queue = kv_num(line, "ul_buf", &l->queue) || kv_num(line, "bsr", &l->queue); /* exact buffer if logged */
    l->has_ul = kv_num(line, "ul_rate", &l->ul_rate);
    l->has_standing = kv_num(line, "qdelay_min", &l->qdelay_min);
    if (l->has_standing && !kv_num(line, "ul_buf_min", &l->queue_min)) /* only bsr on this modem: back from the delay */
        l->queue_min = l->qdelay_min / 1000 * (l->has_ul && l->ul_rate > 0.5 ? l->ul_rate : 0.5) * 1000 / 8; /* KB */
    l->has_trigger = kv_str(line, "trigger", l->trigger, sizeof(l->trigger)) && kv_num(line, "trigger_gap", &l->trigger_gap);
    l->has_cell = kv_num(line, "earfcn", &l->earfcn) && kv_num(line, "pci", &l->pci);
    return 1;
}

/* ---- state and reporting (stdout and, with GROUND_IP, the ground station) */
typedef struct {
    int enabled;
    const preset_t *p;
    long current;      /* kbit/s the encoder has (the overshoot loop's); 0 until the camera has answered */
    long target;       /* kbit/s the link should carry (the link loop's); the encoder never goes above it */
    double target_change; /* when the link loop last changed it */
    long manual;       /* kbit/s to give back: the camera's when modem_alink took over, or someone else's last change */
    int fps, fps_full; /* current frame rate, and the one to give back */
    int camera_ok;     /* -1 until the first poll, so the first failure is reported */
    int was_congested, stats_ok;
    double last_queue; /* KB on the previous stats line */
    double last_change, clear_since, last_stats, fps_retry;
    double cap, cap_time; /* kbit/s the uplink carried on the last congested line, and when */
    int edge;             /* a network rule is close to firing (EDGE_GAP) */
    int cell;             /* serving cell: 0 not seen yet, 1 there (earfcn, pci), 2 lost */
    double earfcn, pci, grace_until;
    int fps_cap;          /* frame rate allowed at the bitrate floor (fps_full when not dropping) */
    long actual;          /* kbit/s the stream measures over FD_WINDOW, -1 unknown */
    char iface[32];       /* interface the stream leaves on */
    int iface_hdr;        /* non-video bytes per packet on it */
    double iface_next, fd_next, fd_last_change;
    struct { double t, bytes, pkts; } fd_ring[16];
    int fd_n, fd_head;
    int temp, therm_fps, therm_level; /* degrees C (-1 unknown), thermal frame-rate cap (0 none), profile line */
    double therm_next;
    double os_ok_since;   /* overshoot loop: output below OS_BACK x the target since, -1 not */
    double up_wait, last_up, last_down; /* the ladder: s between steps back up, and when it last went up / down */
    int os_control;       /* overshoot loop moves the encoder (ALINK_BITRATE_OVERSHOOT_CONTROL, control port) */
    int strained;         /* the last stats line: the link not clear (a standing queue building) or congested */
    const algo_t *al;     /* overshoot loop algorithm (ALINK_ALGO, control port) */
    double os_max;        /* its threshold (ALINK_BITRATE_OVERSHOOT_MAX, control port) */
    double probe_fill;    /* the link loop raises the target only at this output/target (ALINK_PROBE_FILL); 0 = always */
    int isp[ISP_N];       /* ISP settings kept on the camera (ALINK_ISP_*, control port), -1 = left alone */
    int isp_floor;        /* the floor's ISP stage is on: ISP_FLOOR is kept instead of isp[] */
    int isp_saved[ISP_N]; /* the camera's values before it, to put back where isp[] is -1 */
    double isp_next;      /* next check */
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
    size_t n = snprintf(o, size, "ALINK;time=%s;enabled=%d;preset=%s;bitrate=%ldkbps;target=%ldkbps;max=%ldkbps;fps=%d",
                        tm, a->enabled, a->p->name, a->current, a->target, a->p->max_bitrate, a->fps);
    if (a->actual >= 0 && n < size)
        n += snprintf(o + n, size - n, ";actual=%ldkbps;fps_cap=%d", a->actual, a->fps_cap);
    if (a->temp >= 0 && n < size)
        n += snprintf(o + n, size - n, ";temp=%dC;therm_fps=%d", a->temp, a->therm_fps);
    if (n < size)
        n += snprintf(o + n, size - n, ";overshoot_control=%d;overshoot_max=%.2f;algo=%s;probe_fill=%.2f", a->os_control,
                      a->os_max, a->al->name, a->probe_fill);
    for (int i = 0; i < ISP_N && n < size; i++)
        n += snprintf(o + n, size - n, ";%s=%d", ISP_KEYS[i].ctl, a->isp[i]);
    if (n < size)
        n += snprintf(o + n, size - n, ";isp_floor=%d", a->isp_floor);
    return n < size ? n : size - 1;
}

static size_t num_or_na(char *o, size_t size, const char *key, int ok, double v, int prec, const char *unit)
{
    return ok ? snprintf(o, size, ";%s=%.*f%s", key, prec, v, unit) : snprintf(o, size, ";%s=NA", key);
}

static void report(const alink_t *a, const char *reason, long prev, const link_t *l)
{
    char line[640];
    size_t n = status_core(a, line, sizeof(line));
    n += snprintf(line + n, sizeof(line) - n, ";prev=%ldkbps;reason=%s", prev, reason);
    if (l) {
        n += num_or_na(line + n, sizeof(line) - n, "qdelay", l->has_qdelay, l->qdelay, 0, "ms");
        n += num_or_na(line + n, sizeof(line) - n, "queue", l->has_queue, l->queue, 1, "KB");
        n += num_or_na(line + n, sizeof(line) - n, "ul_rate", l->has_ul, l->ul_rate, 2, "Mbps");
        n += num_or_na(line + n, sizeof(line) - n, "qdelay_min", l->has_standing, l->qdelay_min, 0, "ms");
        n += num_or_na(line + n, sizeof(line) - n, "queue_min", l->has_standing, l->queue_min, 1, "KB");
        n += snprintf(line + n, sizeof(line) - n, ";trigger=%s", l->has_trigger ? l->trigger : "NA");
        n += num_or_na(line + n, sizeof(line) - n, "trigger_gap", l->has_trigger, l->trigger_gap, 1, "dB");
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

static long clamp(const alink_t *a, const conf_t *c, long target);

/* re-reads the bitrate; a value modem_alink did not set (e.g. from the bitrate slider) is the new target, where it
 * carries on from and what it gives back later, and then 1 is returned. Within 2 % it is the camera rounding what
 * modem_alink set. */
static int camera_sync(alink_t *a, const conf_t *c)
{
    long b = camera_get(c, "video0.bitrate");
    if (b <= 0) {
        camera_down(a, c);
        return 0;
    }
    a->camera_ok = 1;
    if (a->fps != a->fps_full) { /* we lowered it: an encoder restart puts the configured rate back */
        long f = camera_get(c, "video0.fps");
        if (f > 0 && f != a->fps)
            a->fps = (int)f; /* the next fps_update sets ours again */
    }
    if (labs(b - a->current) > a->current / 50) {
        long prev = a->current;
        a->current = a->manual = b;
        a->target = clamp(a, c, b);
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
    long lo = c->min_bitrate > c->enc_min ? c->min_bitrate : c->enc_min; /* the encoder goes no lower anyway */
    if (lo > hi) lo = hi;
    if (target < lo) target = lo;
    if (target > hi) target = hi;
    return target;
}

/* the frame rate: full, or lower at the bitrate floor (fps_cap, while enabled) or when hot (therm_fps, always).
 * Returns 1 if it changed, 0 if not, -1 if the camera refused it. */
static int fps_update_r(alink_t *a, const conf_t *c, const char *reason)
{
    int fps = a->fps_full;
    if (a->enabled && a->fps_cap > 0 && a->fps_cap < fps)
        fps = a->fps_cap;
    if (a->therm_fps > 0 && a->therm_fps < fps)
        fps = a->therm_fps;
    if (fps == a->fps || now() < a->fps_retry)
        return 0;
    if (!camera_set_live(c, "video0.fps", fps)) {
        fprintf(stderr, "camera %s:%s did not accept %d fps\n", c->camera_host, c->camera_port, fps);
        a->fps_retry = now() + FPS_RETRY;
        return -1;
    }
    a->fps = fps;
    report(a, reason, a->current, NULL);
    return 1;
}

static void fps_update(alink_t *a, const conf_t *c) { fps_update_r(a, c, "fps"); }

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

/* the overshoot loop moves the encoder bitrate: ALINK_BITRATE_OVERSHOOT_CONTROL, or an algorithm that ignores the
 * link. Otherwise the encoder bitrate is the target */
static int inner_on(const alink_t *a) { return a->os_control || !a->al->link; }

static int degraded(const alink_t *a);

/* the link loop's only output. The encoder follows at once where it is above the new target, with the overshoot loop
 * off, or where it was at the target and the ladder is off; else the overshoot loop takes it up (the ladder first) */
static void set_target(alink_t *a, const conf_t *c, long target, const char *reason, const link_t *l, double t)
{
    target = clamp(a, c, target);
    if (target == a->target)
        return;
    long prev = a->target;
    a->target = target;
    a->target_change = t;
    if (a->current > target || !inner_on(a) || (a->current >= prev && !degraded(a))) {
        if (apply(a, c, target, reason, l)) {
            a->last_change = t;
            return;
        }
        if (a->target != target)
            return; /* someone else set the bitrate meanwhile: that is the target now */
    }
    report(a, reason, prev, l); /* the target alone */
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
    a->target = clamp(a, c, b);
    int cam_fps = f > 0 ? (int)f : FPS_DEFAULT;
    /* the camera may be at a rate we lowered (thermal, also while disabled): that is not its full rate */
    if (!(a->fps_full > 0 && cam_fps == a->fps && a->fps < a->fps_full))
        a->fps_full = cam_fps;
    a->fps = cam_fps;
    a->fps_cap = a->fps_full;
    a->was_congested = 0;
    a->clear_since = -1;
    report(a, reason, b, NULL);
    if (a->enabled) {
        apply(a, c, a->target, "max", NULL);
        fps_update(a, c);
    }
}

static void isp_floor(alink_t *a, const conf_t *c, double t, int on);

/* gives the camera back what it had when modem_alink took over, or someone else's last change */
static void release(alink_t *a, const conf_t *c, const char *reason)
{
    if (!a->current)
        return;
    long prev = a->current;
    camera_sync(a, c); /* a change from someone else just now is what stays */
    if (a->current != a->manual && camera_set(c, "video0.bitrate", a->manual))
        a->current = a->manual;
    a->fps_cap = a->fps_full;
    if (a->isp_floor)
        isp_floor(a, c, now(), 0);
    /* the frame rate goes back too, but not above the thermal cap while alink keeps running */
    int back = strcmp(reason, "exit") && a->therm_fps > 0 && a->therm_fps < a->fps_full ? a->therm_fps : a->fps_full;
    if (a->fps != back && camera_set_live(c, "video0.fps", back))
        a->fps = back;
    report(a, reason, prev, NULL);
}

/* the network's view of the link from modem_link's trigger and serving cell: sets a->edge, a->cell, a->grace_until */
static void link_state(alink_t *a, const link_t *l, double t)
{
    /* entered at EDGE_GAP, left 1 dB above it so a gap hovering at the threshold does not report on every line */
    int edge = l->has_trigger && strncmp(l->trigger, "A1", 2) && l->trigger_gap <= EDGE_GAP + (a->edge ? 1 : 0);
    if (edge && !a->edge)
        report(a, "edge", a->current, l);
    a->edge = edge;
    if (l->has_cell) {
        if (a->cell == 2 || (a->cell == 1 && (l->earfcn != a->earfcn || l->pci != a->pci))) {
            a->grace_until = t + HO_GRACE;
            report(a, a->cell == 2 ? "service" : "handover", a->current, l);
        }
        a->cell = 1;
        a->earfcn = l->earfcn;
        a->pci = l->pci;
    } else if (a->cell == 1) {
        a->cell = 2;
        report(a, "no_service", a->current, l);
    }
}

/* ---- frame rate at the bitrate floor */
static int read_counter(const char *iface, const char *name, double *v)
{
    char path[96];
    snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/%s", iface, name);
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    unsigned long long x;
    int ok = fscanf(f, "%llu", &x) == 1;
    fclose(f);
    *v = (double)x;
    return ok;
}

/* the interface the stream leaves on: ALINK_IFACE, or the most specific route to waybeam's outgoing.server */
static void fd_iface(alink_t *a, const conf_t *c, double t)
{
    if (t < a->iface_next)
        return;
    a->iface_next = t + FD_IFACE_EVERY;
    char name[32] = "";
    if (strcmp(c->iface, "auto")) {
        snprintf(name, sizeof(name), "%s", c->iface);
    } else {
        char server[128], host[64];
        if (!camera_get_str(c, "outgoing.server", server, sizeof(server)))
            return; /* keep what we had */
        const char *h = strstr(server, "://");
        h = h ? h + 3 : server;
        snprintf(host, sizeof(host), "%.*s", (int)strcspn(h, ":/"), h);
        struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_DGRAM }, *res;
        if (!*host || getaddrinfo(host, NULL, &hints, &res) != 0)
            return;
        uint32_t dst = ((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr;
        freeaddrinfo(res);
        FILE *f = fopen("/proc/net/route", "r");
        if (!f)
            return;
        char line[256], ifn[32];
        unsigned int d, g, fl, m;
        int best = -1;
        while (fgets(line, sizeof(line), f)) /* addresses are hex in memory order, as s_addr */
            if (sscanf(line, "%31s %x %x %x %*d %*d %*d %x", ifn, &d, &g, &fl, &m) == 5 && (fl & 1) && (dst & m) == d &&
                __builtin_popcount(m) > best) {
                best = __builtin_popcount(m);
                snprintf(name, sizeof(name), "%s", ifn);
            }
        fclose(f);
    }
    if (strcmp(name, a->iface)) {
        snprintf(a->iface, sizeof(a->iface), "%s", name);
        a->fd_n = 0;
        a->iface_hdr = FD_HDR;
        char path[96];
        snprintf(path, sizeof(path), "/sys/class/net/%s/type", name);
        FILE *f = fopen(path, "r");
        int type = 0;
        if (f) {
            if (fscanf(f, "%d", &type) != 1) type = 0;
            fclose(f);
        }
        if (type == 1) /* ARPHRD_ETHER: the counters include the 14-byte Ethernet header */
            a->iface_hdr += 14;
        fprintf(stderr, "measuring the stream on %s\n", *name ? name : "(no route)");
    }
}

/* what the stream actually sends, kbit/s over FD_WINDOW (a->actual) */
static void fd_measure(alink_t *a, const conf_t *c, double t)
{
    fd_iface(a, c, t);
    if (!*a->iface || t < a->fd_next)
        return;
    a->fd_next = t + FD_SAMPLE;
    double bytes, pkts;
    if (!read_counter(a->iface, "tx_bytes", &bytes) || !read_counter(a->iface, "tx_packets", &pkts)) {
        a->actual = -1;
        a->fd_n = 0;
        return;
    }
    const int N = sizeof(a->fd_ring) / sizeof(a->fd_ring[0]);
    a->fd_ring[a->fd_head].t = t;
    a->fd_ring[a->fd_head].bytes = bytes;
    a->fd_ring[a->fd_head].pkts = pkts;
    int newest = a->fd_head;
    a->fd_head = (a->fd_head + 1) % N;
    if (a->fd_n < N)
        a->fd_n++;
    for (int k = 1; k < a->fd_n; k++) { /* the newest sample at least FD_WINDOW old */
        int i = (newest - k + N) % N;
        if (t - a->fd_ring[i].t < FD_WINDOW)
            continue;
        double dt = t - a->fd_ring[i].t, db = bytes - a->fd_ring[i].bytes, dp = pkts - a->fd_ring[i].pkts;
        if (db < 0 || dp < 0) { /* counters reset */
            a->fd_n = 0;
            return;
        }
        double kbps = (db - dp * a->iface_hdr) * 8 / dt / 1000;
        a->actual = kbps > 0 ? (long)kbps : 0;
        return;
    }
}

/* kbit/s at or below which the ladder runs: the floor, or higher where the preset (ALINK_LADDER_FROM) says so */
static long ladder_from(const alink_t *a, const conf_t *c)
{
    long floor = clamp(a, c, 0), lf = c->ladder_from >= 0 ? c->ladder_from : a->p->ladder_from;
    return lf > floor ? lf : floor;
}

/* the frame rate of the floor's first stage, where the ISP stage (grayscale) comes in: two thirds of the full rate
 * (60 -> 40), not below ALINK_MIN_FPS */
static int gray_fps(const alink_t *a, const conf_t *c)
{
    int h = fd_step(a->fps_full, 1);
    return h < c->min_fps ? c->min_fps : h;
}

/* something of the floor's ladder is on (frame rate or ISP stage): it goes back before the bitrate does */
static int degraded(const alink_t *a) { return a->fps_cap < a->fps_full || a->isp_floor; }

/* the pace back up: normal again after FD_UP_CALM without a step down. Checked before the wait it sets, else a wait
 * doubled to FD_UP_MAX had to run out first */
static void up_pace(alink_t *a, double t)
{
    if (t - a->last_down >= FD_UP_CALM)
        a->up_wait = a->al->gap;
}

/* a step down: if it undoes the last step up, the wait before the next one doubles (once per step up) */
static void stepped_down(alink_t *a, double t)
{
    if (t - a->last_up < a->up_wait + FD_WINDOW + FD_SETTLE + 1) {
        a->up_wait *= 2;
        if (a->up_wait > FD_UP_MAX)
            a->up_wait = FD_UP_MAX;
        a->last_up = -1e9;
    }
    a->last_down = t;
}

/* the next stage of the ladder, with the encoder at its floor (or at ALINK_LADDER_FROM) and the output still r x the
 * target: frame rate to two thirds (60 -> 40), then the ISP stage, then the frame rate one step lower at a time (30,
 * 20, 15 ..., not below ALINK_MIN_FPS); far over (jump) every stage expected to be needed, at once. 1 if it changed */
static int floor_frames(alink_t *a, const conf_t *c, double t, double r, int jump)
{
    int cap = a->fps_cap, isp = a->isp_floor;
    if (jump) {
        /* far over (a dark scene: 5-10x): every stage expected to be needed in one step, not one per measurement */
        double rr = r;
        int base = a->fps, gray = gray_fps(a, c);
        if (a->fps_cap > gray) { /* 1 */
            rr *= (double)gray / base;
            base = gray;
            a->fps_cap = gray;
        }
        if (!a->isp_floor) { /* 2 */
            isp_floor(a, c, t, 1);
            rr /= ISP_GAIN;
        }
        if (rr >= FD_OVER) { /* 3: the step expected to fit */
            double want = base * FD_AIM / rr;
            for (int i = 0; i < FD_NSTEPS; i++) {
                int st = fd_step(a->fps_full, i);
                if (st < base && st >= c->min_fps) {
                    a->fps_cap = st;
                    if (st <= want)
                        break;
                }
            }
        }
    } else if (a->fps_cap > gray_fps(a, c)) { /* 1: a third of the frames off (60 -> 40) */
        a->fps_cap = gray_fps(a, c);
    } else if (!a->isp_floor) { /* 2: less noise to encode */
        isp_floor(a, c, t, 1);
    } else { /* 3: fewer frames still, the next step down (30, 20, 15 ...) */
        int next = -1;
        for (int i = 0; i < FD_NSTEPS && next < 0; i++) {
            int st = fd_step(a->fps_full, i);
            if (st < a->fps && st >= c->min_fps)
                next = st;
        }
        if (next > 0)
            a->fps_cap = next;
    }
    if (a->fps_cap == cap && a->isp_floor == isp)
        return 0; /* at ALINK_MIN_FPS with the ISP stage on: nothing left */
    if (a->fps_cap != cap)
        fps_update_r(a, c, "floor_fps");
    a->fd_last_change = t;
    return 1;
}

/* one stage of the ladder back, as the algorithm says: by default the frame rate up to two thirds (40), the ISP
 * settings back, then the frame rate up to full; gray_last keeps the ISP stage until the full frame rate; UP_COARSE
 * goes to two thirds and full in one stage each, UP_ALL brings everything back at once. With fit a frame-rate stage
 * goes to the highest step the output, scaled by the frame rate, still fits at FD_AIM of the target, at least the next
 * step (skips steps only where the encoder sends well below the target) */
static void frames_up(alink_t *a, const conf_t *c, double t)
{
    const algo_t *al = a->al;
    a->fd_last_change = a->last_up = t;
    int gray = gray_fps(a, c), full = a->fps_full;
    if (al->up == UP_ALL) {
        a->fps_cap = full;
        if (a->isp_floor)
            isp_floor(a, c, t, 0);
        fps_update_r(a, c, "recover_fps");
        return;
    }
    if (a->isp_floor && a->fps_cap >= (al->gray_last ? full : gray)) {
        isp_floor(a, c, t, 0);
        return;
    }
    int up = full;
    if (al->up == UP_COARSE) {
        if (a->fps_cap < gray)
            up = gray;
    } else {
        for (int i = FD_NSTEPS - 1; i >= 0; i--)
            if (fd_step(full, i) > a->fps_cap) {
                up = fd_step(full, i);
                break;
            }
        if (al->fit && a->actual >= 0 && a->target > 0 && a->fps > 0) {
            /* (a keyframe per second whatever the rate: the output grows less than the frame rate, this errs low) */
            double r = a->actual / (a->target * 1.024);
            for (int i = 0; i < FD_NSTEPS; i++) {
                int st = fd_step(full, i);
                if (st <= up)
                    break;
                if (r * st / a->fps <= FD_AIM) {
                    up = st;
                    break;
                }
            }
        }
    }
    if (a->isp_floor && !al->gray_last && up > gray)
        up = gray; /* the ISP stage goes before the frame rate passes two thirds */
    a->fps_cap = up;
    fps_update_r(a, c, "recover_fps");
}

/* the overshoot loop, on every measurement: keeps the output at the target the link loop set (it only reads it), with
 * the encoder bitrate first and, with the encoder at its floor, the ladder; back up the other way round */
static void overshoot_control(alink_t *a, const conf_t *c, double t)
{
    const algo_t *al = a->al;
    const double settle = FD_WINDOW + FD_SETTLE;
    long floor = clamp(a, c, 0);
    int on = inner_on(a);
    if (a->current > a->target || (!on && a->current != a->target)) {
        /* the encoder never above the target; with the overshoot loop off the encoder bitrate is the target */
        if (apply(a, c, a->target, "target", NULL))
            a->last_change = t;
        return;
    }
    if (a->actual < 0 || t - a->last_change < settle || t - a->fd_last_change < settle)
        return; /* no measurement yet, or the window still holds frames from before the last change */
    int link = al->link && a->stats_ok;
    double r = a->actual / (a->target * 1.024); /* against the target, not the encoder (1024 bit/s units) */
    /* too much: ALINK_BITRATE_OVERSHOOT_MAX x the target; while the link is congested anything above it. With the
     * overshoot loop off only that, and only the ladder */
    double over = link && a->was_congested ? FD_OVER : on ? a->os_max : 0;
    if (over > 0 && r >= over) {
        a->os_ok_since = -1;
        if (t - a->last_down < al->down)
            return; /* a slow algorithm: the last step down is too recent */
        int jump = al->jump > 0 && r >= al->jump;
        if (on && a->current > floor) {
            /* the encoder by the overshoot, so the output should land at the target; far over straight to its floor.
             * The aggressive preset (ALINK_LADDER_FROM) takes a stage of the ladder alongside */
            long prev = a->current;
            if (apply(a, c, jump ? floor : (long)(a->current / r), "overshoot", NULL))
                a->last_change = t;
            int ladder = (jump || a->current > floor) && a->current <= ladder_from(a, c) && floor_frames(a, c, t, r, jump);
            if (ladder || a->current != prev)
                stepped_down(a, t); /* (a step up undone: the next one waits longer) */
        } else if (a->current <= ladder_from(a, c) && floor_frames(a, c, t, r, jump))
            stepped_down(a, t);
        return;
    }
    /* up: room under the target, or (for the ladder) the encoder holding the output to its own bitrate: the ladder is
     * only there for an encoder at its floor that sends more than it is told, a stage back is the encoder's again */
    int room = r < OS_BACK;
    int enc_holds = a->current > floor && a->actual <= a->current * 1.024 * FD_OVER;
    if (!(room || (enc_holds && degraded(a))) || (link && a->strained)) {
        a->os_ok_since = -1;
        return; /* no room for more, or the link struggling */
    }
    if (a->os_ok_since < 0)
        a->os_ok_since = t;
    up_pace(a, t);
    if (t - a->os_ok_since < (al->hold > 0 ? al->hold : a->p->up_after) || t - a->fd_last_change < a->up_wait ||
        t - a->last_change < a->up_wait)
        return;
    if (degraded(a)) {
        frames_up(a, c, t); /* the ladder first: frame rate up to 40, the ISP settings back, frame rate to full */
    } else if (on && room && a->current < a->target) {
        /* then the encoder bitrate, to where the output should fill the target, never above it */
        double to = a->current / (r > 0 ? r : 1e-3);
        if (al->raise > 0 && to > a->current * al->raise)
            to = a->current * al->raise;
        if (to > a->target)
            to = a->target;
        if (apply(a, c, (long)to, "fill", NULL))
            a->last_change = a->last_up = t;
    }
}

/* ---- thermal throttling */
typedef struct { int min, max, fps; double scale, update; } therm_line_t;

/* /etc/temp_profile.conf: "<min>-<max> <fps|-> <scale|-> <update s>"; built-in default if missing */
static int therm_profile(const conf_t *c, therm_line_t *p)
{
    int n = 0;
    FILE *f = fopen(c->temp_profile, "r");
    if (f) {
        char line[160], fps[16], scale[16], upd[16];
        int lo, hi;
        while (n < THERM_MAX && fgets(line, sizeof(line), f)) {
            if (line[0] == '#' || line[0] == '\n')
                continue;
            int k = sscanf(line, "%d-%d %15s %15s %15s", &lo, &hi, fps, scale, upd);
            if (k < 2) {
                k = sscanf(line, "%d%*[+-] %15s %15s %15s", &lo, fps, scale, upd);
                hi = 9999;
                if (k < 1) continue;
                k++;
            }
            p[n].min = lo;
            p[n].max = hi;
            p[n].fps = k >= 3 && strcmp(fps, "-") ? atoi(fps) : 0;
            p[n].scale = k >= 4 && strcmp(scale, "-") ? atof(scale) : 0;
            p[n].update = k >= 5 && strcmp(upd, "-") ? atof(upd) : 5;
            n++;
        }
        fclose(f);
    }
    if (!n) { /* the profile the camera ships with */
        const therm_line_t def[] = { { 0, 70, 0, 1, 5 }, { 70, 80, 0, 0.5, 5 }, { 80, 85, 15, 0, 5 }, { 85, 999, 3, 0, 5 } };
        memcpy(p, def, sizeof(def));
        n = sizeof(def) / sizeof(def[0]);
    }
    return n;
}

static void thermal(alink_t *a, const conf_t *c, double t)
{
    if (!c->thermal || t < a->therm_next)
        return;
    a->therm_next = t + 5;
    FILE *f = fopen(THERM_TEMP, "r");
    if (!f)
        return;
    char buf[64];
    int temp = -1;
    if (fgets(buf, sizeof(buf), f)) {
        char *p = buf + strcspn(buf, "0123456789");
        if (*p) temp = atoi(p);
    }
    fclose(f);
    if (temp < 0)
        return;
    a->temp = temp;
    therm_line_t prof[THERM_MAX];
    int n = therm_profile(c, prof), level = -1;
    for (int i = 0; i < n; i++)
        if (temp >= prof[i].min && temp <= prof[i].max) {
            level = i;
            break;
        }
    if (level < 0)
        return;
    /* cooler band: only once THERM_HYST below the hotter one, so a temperature on the edge does not flap */
    if (a->therm_level >= 0 && level < a->therm_level && level < n && temp > prof[a->therm_level].min - THERM_HYST)
        level = a->therm_level;
    a->therm_next = t + (prof[level].update > 0 ? prof[level].update : 5);
    int fps = prof[level].fps > 0 ? prof[level].fps
            : prof[level].scale > 0 && prof[level].scale < 1 ? (int)(a->fps_full * prof[level].scale) : 0;
    if (fps >= a->fps_full)
        fps = 0;
    a->therm_level = level;
    if (fps != a->therm_fps) {
        a->therm_fps = fps;
        if (fps_update_r(a, c, "thermal") == 0)
            report(a, "thermal", a->current, NULL); /* the cap changed without changing the frame rate */
    }
}

/* the link loop, on every stats line: the target, and nothing else */
static void control(alink_t *a, const conf_t *c, const link_t *l, double t)
{
    const preset_t *p = a->p;
    link_state(a, l, t);
    if (!a->al->link) { /* fixed_*: the link ignored, the target stays at the bitrate that was set */
        a->was_congested = a->strained = 0;
        set_target(a, c, a->manual, "max", l, t);
        return;
    }
    int grace = t < a->grace_until, hold_up = a->edge || grace || a->cell == 2;
    int congested, clear;
    double drain_kb; /* what has to be drained: the standing queue (a keyframe spike drains by itself) */
    if (l->has_standing) {
        congested = (l->qdelay_min >= p->qmin_high && l->queue_min >= p->qbytes_min) ||
                    (p->qbytes_high > 0 && l->queue_min >= p->qbytes_high);
        clear = l->qdelay_min < p->qmin_clear || l->queue_min < p->qbytes_clear;
        drain_kb = l->queue_min;
    } else { /* older modem_link: interval average */
        congested = l->has_queue && ((l->has_qdelay && l->qdelay >= p->qdelay_high && l->queue >= p->qbytes_min) ||
                                     (p->qbytes_high > 0 && l->queue >= p->qbytes_high));
        clear = !l->has_queue || l->queue < p->qbytes_clear || (l->has_qdelay && l->qdelay < p->qdelay_clear);
        drain_kb = l->queue;
    }
    if (a->target > p->max_bitrate) {
        set_target(a, c, p->max_bitrate, "max", l, t);
    } else if (congested) {
        a->clear_since = -1;
        double target = a->target * p->down_factor;
        int cut;
        if (l->has_ul) {
            a->cap = l->ul_rate * 1000; /* with a queue waiting, the modem sends all the link gives it */
            a->cap_time = t;
            double aim = a->cap * p->ul_share - drain_kb * 8 / p->drain; /* kbit/s */
            cut = a->target > aim;
            if (aim < target)
                target = aim;
        } else
            cut = !a->was_congested || drain_kb >= a->last_queue; /* no rate: cut again only while the queue grows */
        if (target < a->target * p->cut_floor)
            target = a->target * p->cut_floor;
        if (cut && !grace && t - a->target_change >= MIN_GAP)
            set_target(a, c, (long)target, "congestion", l, t);
    } else if (clear) {
        if (a->clear_since < 0)
            a->clear_since = t;
        /* raised only while the output fills probe_fill of it: a clear link says nothing about more than it is sent
         * (0, or the output unknown: raised all the same) */
        int filled = a->probe_fill <= 0 || a->actual < 0 || a->actual >= a->target * 1.024 * a->probe_fill;
        if (!hold_up && filled && a->target < p->max_bitrate && t - a->clear_since >= p->up_after &&
            t - a->target_change >= MIN_GAP) {
            long step = (long)(a->target * p->up_step);
            if (t - a->cap_time >= CAP_VALID && step < p->max_bitrate * PROBE_STEP)
                step = (long)(p->max_bitrate * PROBE_STEP);
            /* back at what the link carried within the last CAP_VALID s: that is where it congested, approach it
             * gently (a clear standing queue is common between congestions, full-speed steps just hit it again) */
            if (t - a->cap_time < CAP_VALID && a->target >= a->cap * p->ul_share)
                step /= 4;
            if (step < UP_MIN_STEP) step = UP_MIN_STEP;
            long target = a->target + step;
            if (t - a->cap_time < CAP_VALID && a->cap * p->ul_share > target)
                target = (long)(a->cap * p->ul_share); /* queue drained: back to what the link carried */
            set_target(a, c, target, "recover", l, t);
        }
    } else
        a->clear_since = -1;
    a->was_congested = congested;
    a->strained = congested || !clear;
    a->last_queue = l->has_standing ? l->queue_min : l->has_queue ? l->queue : 0;
    fps_update(a, c); /* also follows a bitrate someone else set */
}

/* ---- ISP settings kept on the camera */

/* the value of `name` in /api/v1/iq ({"name":{...,"value":N}} or {"name":{"value":true}}), -1 if not found */
static int iq_value(const char *body, const char *name)
{
    char pat[48];
    snprintf(pat, sizeof(pat), "\"%s\":{", name);
    const char *p = strstr(body, pat);
    if (!p || !(p = strstr(p, "\"value\":")))
        return -1;
    p += 8;
    if (!strncmp(p, "true", 4)) return 1;
    if (!strncmp(p, "false", 5)) return 0;
    return *p >= '0' && *p <= '9' ? atoi(p) : -1;
}

/* sets the managed ISP settings the camera does not have (waybeam drops them on every start/reinit) */
static void isp_keep(alink_t *a, const conf_t *c, double t)
{
    if (t < a->isp_next)
        return;
    a->isp_next = t + ISP_EVERY;
    int any = a->isp_floor, want[ISP_N];
    for (int i = 0; i < ISP_N; i++) {
        want[i] = a->isp_floor ? ISP_FLOOR[i] : a->isp[i];
        any |= a->isp[i] >= 0;
    }
    if (!any)
        return;
    static char body[8192];
    if (http_get(c, "/api/v1/iq", body, sizeof(body)) != 200)
        return; /* camera not up yet: next time */
    int changed = 0;
    for (int i = 0; i < ISP_N; i++) {
        if (want[i] < 0 || iq_value(body, ISP_KEYS[i].iq) == want[i])
            continue;
        char path[64], reply[256];
        snprintf(path, sizeof(path), "/api/v1/iq/set?%s=%d", ISP_KEYS[i].iq, want[i]);
        if (http_get(c, path, reply, sizeof(reply)) == 200)
            changed = 1;
        else
            fprintf(stderr, "camera %s:%s did not accept %s=%d\n", c->camera_host, c->camera_port, ISP_KEYS[i].iq, want[i]);
    }
    if (changed && !a->isp_floor)
        report(a, "isp", a->current, NULL);
}

/* the floor's ISP stage on (the camera's values kept first) or off (configured values, else those kept, put back;
 * a setting the camera had on auto comes back as a fixed value until waybeam restarts) */
static void isp_floor(alink_t *a, const conf_t *c, double t, int on)
{
    static char body[8192];
    if (on) {
        int got = http_get(c, "/api/v1/iq", body, sizeof(body)) == 200;
        for (int i = 0; i < ISP_N; i++)
            a->isp_saved[i] = got ? iq_value(body, ISP_KEYS[i].iq) : -1;
    }
    a->isp_floor = on;
    if (!on)
        for (int i = 0; i < ISP_N; i++) {
            if (a->isp[i] >= 0 || a->isp_saved[i] < 0)
                continue; /* configured ones: isp_keep sets them back */
            char path[64], reply[256];
            snprintf(path, sizeof(path), "/api/v1/iq/set?%s=%d", ISP_KEYS[i].iq, a->isp_saved[i]);
            http_get(c, path, reply, sizeof(reply));
        }
    a->isp_next = 0;
    isp_keep(a, c, t); /* at once */
    report(a, on ? "floor_isp" : "recover_isp", a->current, NULL);
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
        } else if (!strcmp(tok, "bitrate_overshoot_control")) {
            int on = truthy(v);
            if (on < 0) {
                ok = 0;
            } else if (on != a->os_control) {
                a->os_control = on;
                a->os_ok_since = -1;
                report(a, on ? "overshoot_control_on" : "overshoot_control_off", a->current, NULL);
                if (!on && a->enabled && a->current) { /* give back what it was holding down */
                    if (a->isp_floor)
                        isp_floor(a, c, now(), 0);
                    if (a->fps_cap < a->fps_full) {
                        a->fps_cap = a->fps_full;
                        fps_update_r(a, c, "fps");
                    }
                    if (a->current != a->target) /* the encoder bitrate is the target again */
                        apply(a, c, a->target, "overshoot_control_off", NULL);
                }
            }
        } else if (!strncmp(tok, "isp_", 4)) {
            int i = 0;
            while (i < ISP_N && strcmp(tok, ISP_KEYS[i].ctl))
                i++;
            char *end;
            long x = strtol(v, &end, 10);
            if (i == ISP_N || end == v || *end || x < -1 || x > ISP_KEYS[i].max) {
                ok = 0;
            } else {
                a->isp[i] = (int)x; /* -1: left alone from now on (the value stays until waybeam restarts) */
                a->isp_next = 0;    /* set it at once */
            }
        } else if (!strcmp(tok, "bitrate_overshoot_max")) {
            char *end;
            double x = strtod(v, &end);
            if (end == v || x <= 0) {
                ok = 0;
            } else {
                a->os_max = x < 1.05 ? 1.05 : x;
                report(a, "overshoot_max", a->current, NULL);
            }
        } else if (!strcmp(tok, "probe_fill")) {
            char *end;
            double x = strtod(v, &end);
            if (end == v || *end || x < 0 || x > 1) {
                ok = 0;
            } else if (x != a->probe_fill) {
                a->probe_fill = x;
                report(a, "probe_fill", a->current, NULL);
            }
        } else if (!strcmp(tok, "algo")) {
            const algo_t *al = algo_find(v);
            if (!al) {
                ok = 0;
            } else if (al != a->al) {
                a->al = al;
                a->up_wait = al->gap;
                report(a, "algo", a->current, NULL);
                if (!al->link && a->enabled && a->current) /* the link ignored: the target is the set bitrate */
                    set_target(a, c, a->manual, "algo", NULL, now());
            }
        } else if (!strcmp(tok, "preset")) {
            const preset_t *p = preset_find(v);
            if (!p) {
                ok = 0;
            } else if (p != a->p) {
                a->p = p;
                report(a, "preset", a->current, NULL);
                if (a->enabled && a->target > p->max_bitrate)
                    set_target(a, c, p->max_bitrate, "max", NULL, now());
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
        char status[512], resp[768];
        status_reply(a, ok, status, sizeof(status));
        int len = snprintf(resp, sizeof(resp), "HTTP/1.0 %s\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n%s",
                           ok ? "200 OK" : "400 Bad Request", status);
        send(fd, resp, len, MSG_NOSIGNAL);
    }
    close(fd);
}

static void control_udp(alink_t *a, const conf_t *c)
{
    char buf[512], status[512];
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
    static alink_t a = { .camera_ok = -1, .stats_ok = 1, .last_change = -1e9, .clear_since = -1, .cap_time = -1e9,
                         .actual = -1, .fd_last_change = -1e9, .temp = -1, .therm_level = -1, .os_ok_since = -1,
                         .last_up = -1e9, .last_down = -1e9, .target_change = -1e9 };
    const char *name = argc > 1 ? argv[1] : c.preset;
    if (!(a.p = preset_find(name))) {
        fprintf(stderr, "unknown preset %s (performance, balanced, quality), using balanced\n", name);
        a.p = preset_find("balanced");
    }
    a.enabled = c.enabled;
    a.os_control = c.os_control;
    a.os_max = c.os_max;
    a.probe_fill = c.probe_fill;
    if (!(a.al = algo_find(c.algo))) {
        fprintf(stderr, "unknown ALINK_ALGO %s, using " ALGO_DEFAULT "\n", c.algo);
        a.al = algo_find(ALGO_DEFAULT);
    }
    a.up_wait = a.al->gap;
    memcpy(a.isp, c.isp, sizeof(a.isp));
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
        if (a.enabled && a.current) {
            fd_measure(&a, &c, t);
            overshoot_control(&a, &c, t);
        }
        if (a.current)
            thermal(&a, &c, t); /* also while disabled: it protects the camera */
        isp_keep(&a, &c, t);    /* also while disabled: image settings, not the bitrate */
        if (a.enabled && a.current && a.stats_ok && t - a.last_stats >= STATS_TIMEOUT) {
            a.stats_ok = 0;
            report(&a, "no_data", a.current, NULL); /* the target stays where it is until stats come back */
        }
    }
    if (a.enabled)
        release(&a, &c, "exit");
    return 0;
}
