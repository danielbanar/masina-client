/* Minimal LTE RRC (3GPP 36.331, UPER) decoding for mobility events - C port of lte_rrc.py (same output).
 * Message type, measurement configuration (measured frequencies, A1-A5 / B1-B2 events and thresholds, measIds,
 * gaps), measurement reports, handover target, connection setup / release / re-establishment causes.
 * Checked against pycrate by test_lte_rrc.py (via test_rrc.c). Plain C99, no dependencies. */
#ifndef LTE_RRC_H
#define LTE_RRC_H
#include <setjmp.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* ---- bit reader; errors (short message, unsupported structure) jump back to the decode entry point */
typedef struct {
    const uint8_t *d;
    int n, p;
    jmp_buf jb;
    const char *err;
} ubits_t;

static void ub_fail(ubits_t *b, const char *why)
{
    b->err = why;
    longjmp(b->jb, 1);
}

static uint32_t ub(ubits_t *b, int w)
{
    if (b->p + w > b->n) ub_fail(b, "message too short");
    uint32_t x = 0;
    for (int i = 0; i < w; i++, b->p++)
        x = x << 1 | (b->d[b->p >> 3] >> (7 - (b->p & 7)) & 1);
    return x;
}

static void ub_skip(ubits_t *b, long w)
{
    if (b->p + w > b->n) ub_fail(b, "message too short");
    b->p += w;
}

/* unconstrained length determinant (open types) */
static int ub_length(ubits_t *b)
{
    int x = ub(b, 8);
    if (x < 128) return x;
    if (x >> 6 == 2) return (x & 63) << 8 | ub(b, 8);
    ub_fail(b, "fragmented length");
    return 0;
}

static void ub_open(ubits_t *b) { ub_skip(b, 8L * ub_length(b)); }

/* normally small non-negative whole number */
static uint32_t ub_small(ubits_t *b)
{
    if (ub(b, 1) == 0) return ub(b, 6);
    int n = ub_length(b);
    if (n > 4) ub_fail(b, "large number");
    return ub(b, 8 * n);
}

/* skip the extension additions of a SEQUENCE whose extension bit was set */
static void ub_ext(ubits_t *b)
{
    if (ub(b, 1)) ub_fail(b, "more than 64 extension additions");
    int n = ub(b, 6) + 1;
    uint8_t pres[64];
    for (int i = 0; i < n; i++) pres[i] = ub(b, 1);
    for (int i = 0; i < n; i++)
        if (pres[i]) ub_open(b);
}

/* ENUMERATED with extension marker and w-bit root */
static uint32_t ub_enum_ext(ubits_t *b, int w) { return ub(b, 1) ? ub_small(b) + (1u << w) : ub(b, w); }

/* ---- measurement configuration state (deltas from measConfig applied in order) */
#define RRC_MAXID 33
typedef struct {
    char obj[RRC_MAXID][16];   /* measObjectId -> "3500", "utra10700", "geran20", "cdma2000"; "" = none */
    char rep[RRC_MAXID][112];  /* reportConfigId -> "A3[nb>serving+3dB,hys1dB,ttt320ms]"; "" = none */
    uint8_t id_obj[RRC_MAXID], id_rep[RRC_MAXID];  /* measId -> objId, repId (0 = none) */
    char gaps[16];             /* "gp0:25"; "" = off */
} meas_state_t;

static void meas_clear(meas_state_t *st) { memset(st, 0, sizeof(*st)); }

/* "measId:event@earfcn,..." active rules, "none" if empty */
static char *meas_summary(const meas_state_t *st, char *o, size_t sz)
{
    size_t l = 0;
    o[0] = 0;
    for (int m = 1; m < RRC_MAXID; m++) {
        if (!st->id_obj[m]) continue;
        const char *r = st->rep[st->id_rep[m]], *ob = st->obj[st->id_obj[m]];
        l += snprintf(o + l, l < sz ? sz - l : 0, "%s%d:%s@%s", l ? "," : "", m, *r ? r : "?", *ob ? ob : "?");
    }
    if (!o[0]) snprintf(o, sz, "none");
    return o;
}

/* "measId:event@earfcn" for a measurement report */
static char *meas_describe(const meas_state_t *st, int m, char *o, size_t sz)
{
    if (m <= 0 || m >= RRC_MAXID || !st->id_obj[m]) {
        snprintf(o, sz, "%d:?", m);
        return o;
    }
    const char *r = st->rep[st->id_rep[m]], *ob = st->obj[st->id_obj[m]];
    int k = (int)strcspn(r, "[");
    if (*r) snprintf(o, sz, "%d:%.*s@%s", m, k, r, *ob ? ob : "?");
    else snprintf(o, sz, "%d:?@%s", m, *ob ? ob : "?");
    return o;
}

static const int TTT_MS[16] = { 0, 40, 64, 80, 100, 128, 160, 256, 320, 480, 512, 640, 1024, 1280, 2560, 5120 };

/* ThresholdEUTRA -> text */
static void rrc_thr(ubits_t *b, char *o, size_t sz)
{
    if (ub(b, 1) == 0) snprintf(o, sz, "rsrp%ddBm", (int)ub(b, 7) - 140);
    else snprintf(o, sz, "rsrq%gdB", ub(b, 6) / 2.0 - 20);
}

static void rrc_cell_list(ubits_t *b, int extra_bits)
{
    int n = ub(b, 5) + 1;
    for (int i = 0; i < n; i++) {
        ub(b, 5);
        ub_skip(b, extra_bits);
    }
}

static void meas_object_eutra(ubits_t *b, char *o, size_t sz)
{
    int e = ub(b, 1), op[6];
    for (int i = 0; i < 6; i++) op[i] = ub(b, 1);  /* offsetFreq, cellsToRemove, cellsToAddMod, black rm/add, CGI */
    unsigned earfcn = ub(b, 16);
    ub(b, 3);
    ub(b, 1);
    ub(b, 2);
    if (op[0]) ub(b, 5);
    if (op[1]) rrc_cell_list(b, 0);
    if (op[2]) rrc_cell_list(b, 9 + 5);
    if (op[3]) rrc_cell_list(b, 0);
    if (op[4]) {
        int n = ub(b, 5) + 1;
        for (int i = 0; i < n; i++) {
            ub(b, 5);
            int r = ub(b, 1);
            ub(b, 9);
            if (r) ub(b, 4);
        }
    }
    if (op[5]) ub(b, 9);
    if (e) ub_ext(b);
    snprintf(o, sz, "%u", earfcn);
}

static void meas_object_utra(ubits_t *b, char *o, size_t sz)
{
    int e = ub(b, 1), op[4];
    for (int i = 0; i < 4; i++) op[i] = ub(b, 1);
    unsigned arfcn = ub(b, 14);
    if (op[0]) ub(b, 5);
    if (op[1]) rrc_cell_list(b, 0);
    if (op[2]) rrc_cell_list(b, ub(b, 1) == 0 ? 9 : 7);
    if (op[3]) ub(b, ub(b, 1) == 0 ? 9 : 7);
    if (e) ub_ext(b);
    snprintf(o, sz, "utra%u", arfcn);
}

static void meas_object_geran(ubits_t *b, char *o, size_t sz)
{
    int e = ub(b, 1), op[3];
    for (int i = 0; i < 3; i++) op[i] = ub(b, 1);
    unsigned start = ub(b, 10);
    ub(b, 1);
    int c = ub(b, 2);
    if (c == 0) ub_skip(b, 10L * ub(b, 5));
    else if (c == 1) { ub(b, 3); ub(b, 5); }
    else if (c == 2) ub_skip(b, 8L * (ub(b, 4) + 1));
    else ub_fail(b, "GERAN followingARFCNs");
    if (op[0]) ub(b, 5);
    if (op[1]) ub(b, 8);
    if (op[2]) ub(b, 6);
    if (e) ub_ext(b);
    snprintf(o, sz, "geran%u", start);
}

/* append ",hys..dB,ttt..ms]" (or "[hys..]" when the event text has no '[' yet) */
static void rrc_hys_ttt(ubits_t *b, char *ev, size_t sz)
{
    double hys = ub(b, 5) / 2.0;
    int ttt = TTT_MS[ub(b, 4)];
    size_t l = strlen(ev);
    snprintf(ev + l, sz - l, strchr(ev, '[') ? ",hys%gdB,ttt%dms]" : "[hys%gdB,ttt%dms]", hys, ttt);
}

static void report_config_eutra(ubits_t *b, char *ev, size_t sz)
{
    char t1[24], t2[24];
    int e = ub(b, 1);
    if (ub(b, 1) == 0) {  /* event */
        if (ub(b, 1)) {   /* eventA6 and later (extension alternatives) */
            snprintf(ev, sz, "ext%u", ub_small(b) + 5);
            ub_open(b);
        } else {
            int k = ub(b, 3);
            if (k == 0) { rrc_thr(b, t1, sizeof(t1)); snprintf(ev, sz, "A1[serving>%s", t1); }
            else if (k == 1) { rrc_thr(b, t1, sizeof(t1)); snprintf(ev, sz, "A2[serving<%s", t1); }
            else if (k == 2) {
                double off = ((int)ub(b, 6) - 30) / 2.0;
                ub(b, 1);
                snprintf(ev, sz, "A3[nb>serving%+gdB", off);
            } else if (k == 3) { rrc_thr(b, t1, sizeof(t1)); snprintf(ev, sz, "A4[nb>%s", t1); }
            else if (k == 4) {
                rrc_thr(b, t1, sizeof(t1));
                rrc_thr(b, t2, sizeof(t2));
                snprintf(ev, sz, "A5[serving<%s&nb>%s", t1, t2);
            } else
                ub_fail(b, "eventId");
        }
        rrc_hys_ttt(b, ev, sz);
    } else
        snprintf(ev, sz, "%s", ub(b, 1) ? "periodic[cgi]" : "periodic[strongest]");
    ub(b, 1);
    ub(b, 1);
    ub(b, 3);
    ub(b, 4);
    ub(b, 3);
    if (e) ub_ext(b);
}

static void rrc_thr_irat(ubits_t *b, int k, char *o, size_t sz)
{
    if (k == 0) {
        if (ub(b, 1) == 0) snprintf(o, sz, "rscp%d", (int)ub(b, 7) - 5);
        else snprintf(o, sz, "ecn0_%u", ub(b, 6));
    } else
        snprintf(o, sz, "thr%u", ub(b, 6));
}

static void report_config_irat(ubits_t *b, char *ev, size_t sz)
{
    char t1[24], t2[24];
    int e = ub(b, 1);
    if (ub(b, 1) == 0) {
        if (ub(b, 1)) {
            snprintf(ev, sz, "extB%u", ub_small(b) + 2);
            ub_open(b);
        } else if (ub(b, 1) == 0) {
            rrc_thr_irat(b, ub(b, 2), t1, sizeof(t1));
            snprintf(ev, sz, "B1[irat>%s", t1);
        } else {
            rrc_thr(b, t1, sizeof(t1));
            rrc_thr_irat(b, ub(b, 2), t2, sizeof(t2));
            snprintf(ev, sz, "B2[serving<%s&irat>%s", t1, t2);
        }
        rrc_hys_ttt(b, ev, sz);
    } else {
        ub(b, 2);
        snprintf(ev, sz, "periodic[irat]");
    }
    ub(b, 3);
    ub(b, 4);
    ub(b, 3);
    if (e) ub_ext(b);
}

static void rrc_meas_config(ubits_t *b, meas_state_t *st)
{
    char tmp[112];
    int ext = ub(b, 1), o[11];
    for (int i = 0; i < 11; i++) o[i] = ub(b, 1);
    if (o[0]) for (int i = 0, n = ub(b, 5) + 1; i < n; i++) st->obj[ub(b, 5) + 1][0] = 0;
    if (o[1])
        for (int i = 0, n = ub(b, 5) + 1; i < n; i++) {
            int oid = ub(b, 5) + 1;
            if (ub(b, 1)) ub_fail(b, "measObject extension");
            int k = ub(b, 2);
            if (k == 0) meas_object_eutra(b, tmp, sizeof(tmp));
            else if (k == 1) meas_object_utra(b, tmp, sizeof(tmp));
            else if (k == 2) meas_object_geran(b, tmp, sizeof(tmp));
            else {
                snprintf(st->obj[oid], sizeof(st->obj[oid]), "cdma2000");
                ub_fail(b, "CDMA2000 object");
            }
            snprintf(st->obj[oid], sizeof(st->obj[oid]), "%s", tmp);
        }
    if (o[2]) for (int i = 0, n = ub(b, 5) + 1; i < n; i++) st->rep[ub(b, 5) + 1][0] = 0;
    if (o[3])
        for (int i = 0, n = ub(b, 5) + 1; i < n; i++) {
            int rid = ub(b, 5) + 1;
            if (ub(b, 1)) report_config_irat(b, tmp, sizeof(tmp));
            else report_config_eutra(b, tmp, sizeof(tmp));
            snprintf(st->rep[rid], sizeof(st->rep[rid]), "%s", tmp);
        }
    if (o[4]) for (int i = 0, n = ub(b, 5) + 1; i < n; i++) { int m = ub(b, 5) + 1; st->id_obj[m] = st->id_rep[m] = 0; }
    if (o[5])
        for (int i = 0, n = ub(b, 5) + 1; i < n; i++) {
            int m = ub(b, 5) + 1, oid = ub(b, 5) + 1, rid = ub(b, 5) + 1;
            st->id_obj[m] = oid;
            st->id_rep[m] = rid;
        }
    if (o[6]) {  /* quantityConfig */
        int e = ub(b, 1), q[4];
        for (int i = 0; i < 4; i++) q[i] = ub(b, 1);
        if (q[0]) {
            int d0 = ub(b, 1), d1 = ub(b, 1);
            if (d0) ub_enum_ext(b, 4);
            if (d1) ub_enum_ext(b, 4);
        }
        if (q[1]) {
            int d = ub(b, 1);
            ub(b, 1);
            if (d) ub_enum_ext(b, 4);
        }
        if (q[2] && ub(b, 1)) ub_enum_ext(b, 4);
        if (q[3]) ub(b, 1);
        if (e) ub_ext(b);
    }
    if (o[7]) {  /* measGapConfig */
        if (ub(b, 1) == 0)
            st->gaps[0] = 0;
        else {
            if (ub(b, 1)) ub_fail(b, "gap pattern extension");
            int g = ub(b, 1);
            snprintf(st->gaps, sizeof(st->gaps), "gp%d:%u", g, ub(b, g == 0 ? 6 : 7));
        }
    }
    if (o[8]) ub(b, 7);
    if (o[9]) {
        int z = ub(b, 1), s2 = ub(b, 1);
        ub(b, 1);
        if (z) ub(b, 8);
        if (s2) ub_skip(b, 8L * (ub(b, 1) + 1));
    }
    if (o[10] && ub(b, 1)) ub_skip(b, 3 + 3 + 4 + 4 + 2 + 2);
    if (ext) ub_ext(b);
}

/* ---- one decoded message */
typedef struct {
    const char *name;            /* NULL = not a DCCH/CCCH message type handled here */
    int meas_config, handover;
    int target_pci, target_earfcn;  /* -1 = unknown */
    const char *cause;
    int fail_pci;                /* -1 = none */
    int meas_id, have_srv, srv_rsrp;
    double srv_rsrq;
    int ncells;
    struct { int pci, rsrp, have_rsrp, have_rsrq; double rsrq; } cells[8];
    const char *partial;         /* NULL = complete */
} rrc_msg_t;

static const char *RRC_DL_DCCH[16] = { "csfbParametersResponseCDMA2000", "dlInformationTransfer",
    "handoverFromEUTRAPreparationRequest", "mobilityFromEUTRACommand", "rrcConnectionReconfiguration",
    "rrcConnectionRelease", "securityModeCommand", "ueCapabilityEnquiry", "counterCheck", "ueInformationRequest",
    "loggedMeasurementConfiguration", "rnReconfiguration", "rrcConnectionResume", "spare3", "spare2", "spare1" };
static const char *RRC_UL_DCCH[16] = { "csfbParametersRequestCDMA2000", "measurementReport",
    "rrcConnectionReconfigurationComplete", "rrcConnectionReestablishmentComplete", "rrcConnectionSetupComplete",
    "securityModeComplete", "securityModeFailure", "ueCapabilityInformation", "ulHandoverPreparationTransfer",
    "ulInformationTransfer", "counterCheckResponse", "ueInformationResponse", "proximityIndication",
    "rnReconfigurationComplete", "mbmsCountingResponse", "interFreqRSTDMeasurementIndication" };
static const char *RRC_DL_CCCH[4] = { "rrcConnectionReestablishment", "rrcConnectionReestablishmentReject",
    "rrcConnectionReject", "rrcConnectionSetup" };
static const char *RRC_UL_CCCH[2] = { "rrcConnectionReestablishmentRequest", "rrcConnectionRequest" };
static const char *RRC_EST_CAUSE[8] = { "emergency", "highPriorityAccess", "mt-Access", "mo-Signalling", "mo-Data",
    "delayTolerantAccess", "mo-VoiceCall", "spare" };
static const char *RRC_REEST_CAUSE[4] = { "reconfigurationFailure", "handoverFailure", "otherFailure", "spare" };
static const char *RRC_REL_CAUSE[4] = { "loadBalancingTAUrequired", "other", "cs-FallbackHighPriority", "rrc-Suspend" };

static void rrc_meas_report(ubits_t *b, rrc_msg_t *r)
{
    if (ub(b, 1) || ub(b, 3)) ub_fail(b, "measurementReport criticalExtensions");
    ub(b, 1);
    ub(b, 1);
    int nb_present = ub(b, 1);
    int m = ub(b, 5) + 1, rp = (int)ub(b, 7) - 140;
    double rq = ub(b, 6) / 2.0 - 20;
    r->meas_id = m;
    r->srv_rsrp = rp;
    r->srv_rsrq = rq;
    r->have_srv = 1;
    if (!nb_present) return;
    if (ub(b, 1)) ub_fail(b, "neighbour results extension");
    if (ub(b, 2)) ub_fail(b, "non-EUTRA neighbour results");
    for (int i = 0, n = ub(b, 3) + 1; i < n; i++) {
        int cgi = ub(b, 1), pci = ub(b, 9);
        if (cgi) ub_fail(b, "CGI info");
        int e = ub(b, 1), hp = ub(b, 1), hq = ub(b, 1);
        __typeof__(r->cells[0]) *c = &r->cells[r->ncells];
        c->pci = pci;
        c->have_rsrp = hp;
        c->rsrp = hp ? (int)ub(b, 7) - 140 : 0;
        c->have_rsrq = hq;
        c->rsrq = hq ? ub(b, 6) / 2.0 - 20 : 0;
        r->ncells++;
        if (e) ub_ext(b);
    }
}

/* channel names as in lte_rrc.py: "DL_DCCH", "UL_DCCH", "DL_CCCH", "UL_CCCH" (others give name NULL) */
static void rrc_decode(const char *ch, const uint8_t *msg, int len, meas_state_t *st, rrc_msg_t *r)
{
    static ubits_t b;  /* static: values survive longjmp */
    memset(r, 0, sizeof(*r));
    r->target_pci = r->target_earfcn = r->fail_pci = -1;
    b.d = msg;
    b.n = len * 8;
    b.p = 0;
    b.err = NULL;
    if (setjmp(b.jb)) {
        r->partial = b.err;
        return;
    }
    if (!strcmp(ch, "DL_DCCH")) {
        if (ub(&b, 1)) return;
        r->name = RRC_DL_DCCH[ub(&b, 4)];
        if (!strcmp(r->name, "rrcConnectionReconfiguration")) {
            ub(&b, 2);
            if (ub(&b, 1) || ub(&b, 3)) return;
            int o[6];
            for (int i = 0; i < 6; i++) o[i] = ub(&b, 1);
            r->meas_config = o[0];
            r->handover = o[1];
            if (o[0]) rrc_meas_config(&b, st);
            if (o[1]) {  /* MobilityControlInfo */
                ub(&b, 1);
                int op[4];
                for (int i = 0; i < 4; i++) op[i] = ub(&b, 1);
                int pci = ub(&b, 9), earfcn = -1;
                if (op[0]) {
                    int ul = ub(&b, 1);
                    earfcn = ub(&b, 16);
                    if (ul) ub(&b, 16);
                }
                r->target_pci = pci;
                r->target_earfcn = earfcn;
            }
        } else if (!strcmp(r->name, "rrcConnectionRelease")) {
            ub(&b, 2);
            if (ub(&b, 1) == 0 && ub(&b, 2) == 0) {
                ub_skip(&b, 3);
                r->cause = RRC_REL_CAUSE[ub(&b, 2)];
            }
        }
    } else if (!strcmp(ch, "UL_DCCH")) {
        if (ub(&b, 1)) return;
        r->name = RRC_UL_DCCH[ub(&b, 4)];
        if (!strcmp(r->name, "measurementReport")) rrc_meas_report(&b, r);
    } else if (!strcmp(ch, "DL_CCCH")) {
        if (ub(&b, 1) == 0) r->name = RRC_DL_CCCH[ub(&b, 2)];
    } else if (!strcmp(ch, "UL_CCCH")) {
        if (ub(&b, 1) == 0) {
            r->name = RRC_UL_CCCH[ub(&b, 1)];
            if (ub(&b, 1) == 0) {
                if (!strcmp(r->name, "rrcConnectionRequest")) {
                    ub(&b, 1);
                    ub_skip(&b, 40);
                    r->cause = RRC_EST_CAUSE[ub(&b, 3)];
                } else {
                    ub_skip(&b, 16);
                    r->fail_pci = ub(&b, 9);
                    ub_skip(&b, 16);
                    r->cause = RRC_REEST_CAUSE[ub(&b, 2)];
                }
            }
        }
    }
}

/* 0xB0C0 LTE RRC OTA log (v8..v24) -> channel name (NULL if unknown), pci, earfcn, message */
static const char *rrc_ota_msg(const uint8_t *b, int len, int *pci, unsigned *earfcn, const uint8_t **msg, int *mlen)
{
    static const char *CH[10] = { NULL, "BCCH_BCH", "BCCH_DL_SCH", NULL, "MCCH", "PCCH", "DL_CCCH", "DL_DCCH", "UL_CCCH",
                                  "UL_DCCH" };
    if (len < 19 || b[0] < 8 || b[0] >= 25) return NULL;
    *pci = b[4] | b[5] << 8;
    *earfcn = b[6] | b[7] << 8 | b[8] << 16 | (unsigned)b[9] << 24;
    int l = b[17] | b[18] << 8;
    if (l > len - 19) l = len - 19;
    *msg = b + 19;
    *mlen = l;
    return b[12] < 10 ? CH[b[12]] : NULL;
}

/* ---- mobility events: same logic and text as Mobility in lte_link.py */
enum { MOB_SETUP, MOB_RELEASE, MOB_REPORT, MOB_HO, MOB_HO_DONE, MOB_REEST, MOB_NCOUNT };
#define MOB_MAXEV 16
typedef struct {
    meas_state_t meas;
    int full;                   /* measurement rules known completely (seen since a connection setup / release) */
    int have_rules;
    char rules[700], gaps[16];  /* last reported rules */
    int have_setup, have_ho;
    double setup_t, ho_t;       /* modem time of connection setup / pending handover command */
    const char *est_cause, *reason;
    long counts[MOB_NCOUNT];
    int nev;
    struct { double mts; char kv[800]; } ev[MOB_MAXEV];  /* "event=...;key=value;..." */
} mobility_t;

static void mob_ev(mobility_t *m, double mts, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
static void mob_ev(mobility_t *m, double mts, const char *fmt, ...)
{
    if (m->nev == MOB_MAXEV) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(m->ev[m->nev].kv, sizeof(m->ev[0].kv), fmt, ap);
    va_end(ap);
    m->ev[m->nev++].mts = mts;
}

static void mob_rrc(mobility_t *m, double mts, const uint8_t *b, int len)
{
    int pci, mlen;
    unsigned earfcn;
    const uint8_t *msg;
    const char *ch = rrc_ota_msg(b, len, &pci, &earfcn, &msg, &mlen);
    if (!ch) return;
    static rrc_msg_t r;
    rrc_decode(ch, msg, mlen, &m->meas, &r);
    const char *n = r.name;
    char x[24], y[24];
    if (!n) return;
    if (!strcmp(n, "rrcConnectionRequest"))
        m->est_cause = r.cause;
    else if (!strcmp(n, "rrcConnectionSetup")) {
        meas_clear(&m->meas);  /* a new connection starts without measurement configuration */
        m->full = 1;
        m->have_rules = 0;
        m->have_setup = 1;
        m->setup_t = mts;
        m->counts[MOB_SETUP]++;
        mob_ev(m, mts, "event=rrc_setup;cause=%s;pci=%d;earfcn=%u", m->est_cause ? m->est_cause : "NA", pci, earfcn);
    } else if (!strcmp(n, "rrcConnectionReject"))
        mob_ev(m, mts, "event=rrc_reject;pci=%d;earfcn=%u", pci, earfcn);
    else if (!strcmp(n, "rrcConnectionRelease")) {
        if (m->have_setup) snprintf(x, sizeof(x), "%.1fs", mts - m->setup_t);
        else snprintf(x, sizeof(x), "NA");
        m->counts[MOB_RELEASE]++;
        mob_ev(m, mts, "event=rrc_release;cause=%s;connected=%s;pci=%d;earfcn=%u", r.cause ? r.cause : "NA", x, pci, earfcn);
        meas_clear(&m->meas);
        m->full = 1;
        m->have_rules = m->have_setup = m->have_ho = 0;
    } else if (!strcmp(n, "rrcConnectionReestablishmentRequest")) {
        if (r.fail_pci >= 0) snprintf(x, sizeof(x), "%d", r.fail_pci);
        else snprintf(x, sizeof(x), "NA");
        m->counts[MOB_REEST]++;
        mob_ev(m, mts, "event=reestablishment;cause=%s;failed_pci=%s;pci=%d;earfcn=%u", r.cause ? r.cause : "NA", x, pci,
               earfcn);
    } else if (!strcmp(n, "rrcConnectionReestablishment")) {
        mob_ev(m, mts, "event=reestablishment_done;pci=%d;earfcn=%u", pci, earfcn);
        m->have_ho = 0;
    } else if (!strcmp(n, "rrcConnectionReestablishmentReject"))
        mob_ev(m, mts, "event=reestablishment_reject;pci=%d;earfcn=%u", pci, earfcn);
    else if (!strcmp(n, "measurementReport")) {
        char rule[160], cells[400] = "";
        size_t l = 0;
        for (int i = 0; i < r.ncells; i++) {
            if (r.cells[i].have_rsrp) snprintf(x, sizeof(x), "%ddBm", r.cells[i].rsrp);
            else snprintf(x, sizeof(x), "NA");
            if (r.cells[i].have_rsrq) snprintf(y, sizeof(y), "%gdB", r.cells[i].rsrq);
            else snprintf(y, sizeof(y), "NA");
            l += snprintf(cells + l, sizeof(cells) - l, "%s%d:%s:%s", l ? "," : "", r.cells[i].pci, x, y);
        }
        if (r.have_srv) {
            meas_describe(&m->meas, r.meas_id, rule, sizeof(rule));
            snprintf(x, sizeof(x), "%ddBm", r.srv_rsrp);
            snprintf(y, sizeof(y), "%gdB", r.srv_rsrq);
        } else {
            snprintf(rule, sizeof(rule), "NA");
            snprintf(x, sizeof(x), "NA");
            snprintf(y, sizeof(y), "NA");
        }
        m->counts[MOB_REPORT]++;
        mob_ev(m, mts, "event=meas_report;rule=%s;srv_rsrp=%s;srv_rsrq=%s;cells=%s", rule, x, y, cells[0] ? cells : "none");
    } else if (!strcmp(n, "rrcConnectionReconfiguration")) {
        if (r.handover) {
            m->have_ho = 1;
            m->ho_t = mts;
            if (r.target_pci >= 0) snprintf(x, sizeof(x), "%d", r.target_pci);
            else snprintf(x, sizeof(x), "NA");
            if (r.target_earfcn >= 0) snprintf(y, sizeof(y), "%d", r.target_earfcn);
            else if (r.target_pci >= 0) snprintf(y, sizeof(y), "%u", earfcn);  /* no carrierFreq: same frequency */
            else snprintf(y, sizeof(y), "NA");
            m->counts[MOB_HO]++;
            mob_ev(m, mts, "event=handover;from_pci=%d;from_earfcn=%u;to_pci=%s;to_earfcn=%s", pci, earfcn, x, y);
        }
        if (r.meas_config) {
            char rules[700];
            const char *g = m->meas.gaps[0] ? m->meas.gaps : "off";
            meas_summary(&m->meas, rules, sizeof(rules));
            if (!m->have_rules || strcmp(rules, m->rules) || strcmp(g, m->gaps)) {
                m->have_rules = 1;
                snprintf(m->rules, sizeof(m->rules), "%s", rules);
                snprintf(m->gaps, sizeof(m->gaps), "%s", g);
                mob_ev(m, mts, "event=meas_config;rules=%s;gaps=%s;known=%s", rules, g,
                       m->full && !r.partial ? "full" : "partial");
            }
        }
    } else if (!strcmp(n, "rrcConnectionReconfigurationComplete") && m->have_ho) {
        m->counts[MOB_HO_DONE]++;
        mob_ev(m, mts, "event=handover_done;pci=%d;earfcn=%u;duration=%.0fms", pci, earfcn, (mts - m->ho_t) * 1000);
        m->have_ho = 0;
    }
}

/* MAC/RLC subpacket walk for the RACH logs: payload pointer/len of subpacket number i, or NULL */
static const uint8_t *mob_subpkt(const uint8_t *b, int len, int *pos, int *sid, int *ver, int *pl)
{
    if (*pos + 4 > len) return NULL;
    int sz = b[*pos + 2] | b[*pos + 3] << 8;
    if (sz < 4) sz = 4;
    *sid = b[*pos];
    *ver = b[*pos + 1];
    const uint8_t *p = b + *pos + 4;
    *pl = (sz > len - *pos ? len - *pos : sz) - 4;
    *pos += sz;
    return p;
}

static const char *RACH_REASON[5] = { "connection", "rlf", "ul_data", "dl_data", "handover" };

/* 0xB061 MAC RACH trigger: remember the reason for the following attempt */
static void mob_rach_trig(mobility_t *m, const uint8_t *b, int len)
{
    static char other[16];
    int pos = 4, sid, ver, pl;
    m->reason = NULL;
    for (int i = 0; len >= 2 && i < b[1]; i++) {
        const uint8_t *p = mob_subpkt(b, len, &pos, &sid, &ver, &pl);
        if (!p) break;
        if (sid == 5 && pl > 0) {
            int k = ver == 2 && pl > 2 ? p[2] : p[0];
            if (k < 5) m->reason = RACH_REASON[k];
            else { snprintf(other, sizeof(other), "reason%d", k); m->reason = other; }
            return;
        }
    }
}

/* 0xB062 MAC RACH attempt: result, contention, timing advance from the random access response -> distance */
static void mob_rach_att(mobility_t *m, double mts, const uint8_t *b, int len)
{
    int pos = 4, sid, ver, pl;
    for (int i = 0; len >= 2 && i < b[1]; i++) {
        const uint8_t *p = mob_subpkt(b, len, &pos, &sid, &ver, &pl);
        if (!p) break;
        if (sid != 6 || ver < 2 || ver > 4) continue;
        int o = ver == 3 ? 2 : 0;
        if (pl < o + 4) return;
        int res = p[o + 1], cont = p[o + 2], mask = p[o + 3];
        int q = o + 4 + ((mask & 1) ? (ver == 4 ? 5 : 4) : 0);
        char rs[24], ta[16], dist[16];
        if (res == 0) snprintf(rs, sizeof(rs), "success");
        else if (res == 1) snprintf(rs, sizeof(rs), "msg2_fail");
        else if (res == 4) snprintf(rs, sizeof(rs), "aborted");
        else snprintf(rs, sizeof(rs), "result%d", res);
        if ((mask & 2) && q + 7 <= pl) {
            int t = p[q + 5] | p[q + 6] << 8;
            snprintf(ta, sizeof(ta), "%d", t);
            snprintf(dist, sizeof(dist), "%.0fm", t * 78.1);  /* one TA step = 16 Ts round trip = 78.1 m */
        } else {
            snprintf(ta, sizeof(ta), "NA");
            snprintf(dist, sizeof(dist), "NA");
        }
        mob_ev(m, mts, "event=rach;reason=%s;result=%s;contention=%s;ta=%s;distance=%s", m->reason ? m->reason : "NA", rs,
               cont == 0 ? "free" : "based", ta, dist);
        m->reason = NULL;
        return;
    }
}

#endif
