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
enum { MOB_SETUP, MOB_RELEASE, MOB_REPORT, MOB_HO, MOB_HO_DONE, MOB_REEST, MOB_NAS_REJ, MOB_NCOUNT };
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

/* ---- NAS: registration (EMM) and data bearer (ESM) messages between the modem and the core network (3GPP TS 24.301),
 * from the 0xB0EC / 0xB0ED (EMM in / out) and 0xB0E2 / 0xB0E3 (ESM in / out) logs: 4 header bytes (log version, release,
 * major, minor version), then the NAS message, already deciphered ("plain"). */
typedef struct { uint8_t t; const char *n; } nas_name_t;
static const nas_name_t NAS_EMM[] = {
    { 0x41, "attach_request" }, { 0x42, "attach_accept" }, { 0x43, "attach_complete" }, { 0x44, "attach_reject" },
    { 0x45, "detach_request" }, { 0x46, "detach_accept" }, { 0x48, "tau_request" }, { 0x49, "tau_accept" },
    { 0x4a, "tau_complete" }, { 0x4b, "tau_reject" }, { 0x4c, "extended_service_request" },
    { 0x4d, "control_plane_service_request" }, { 0x4e, "service_reject" }, { 0x4f, "service_accept" },
    { 0x50, "guti_reallocation_command" }, { 0x51, "guti_reallocation_complete" }, { 0x52, "authentication_request" },
    { 0x53, "authentication_response" }, { 0x54, "authentication_reject" }, { 0x55, "identity_request" },
    { 0x56, "identity_response" }, { 0x5c, "authentication_failure" }, { 0x5d, "security_mode_command" },
    { 0x5e, "security_mode_complete" }, { 0x5f, "security_mode_reject" }, { 0x60, "emm_status" },
    { 0x61, "emm_information" }, { 0x62, "downlink_nas_transport" }, { 0x63, "uplink_nas_transport" },
    { 0x64, "cs_service_notification" }, { 0x68, "downlink_generic_nas_transport" },
    { 0x69, "uplink_generic_nas_transport" }, { 0, NULL } };
static const nas_name_t NAS_ESM[] = {
    { 0xc1, "activate_default_bearer_request" }, { 0xc2, "activate_default_bearer_accept" },
    { 0xc3, "activate_default_bearer_reject" }, { 0xc5, "activate_dedicated_bearer_request" },
    { 0xc6, "activate_dedicated_bearer_accept" }, { 0xc7, "activate_dedicated_bearer_reject" },
    { 0xc9, "modify_bearer_request" }, { 0xca, "modify_bearer_accept" }, { 0xcb, "modify_bearer_reject" },
    { 0xcd, "deactivate_bearer_request" }, { 0xce, "deactivate_bearer_accept" }, { 0xd0, "pdn_connectivity_request" },
    { 0xd1, "pdn_connectivity_reject" }, { 0xd2, "pdn_disconnect_request" }, { 0xd3, "pdn_disconnect_reject" },
    { 0xd4, "bearer_resource_allocation_request" }, { 0xd5, "bearer_resource_allocation_reject" },
    { 0xd6, "bearer_resource_modification_request" }, { 0xd7, "bearer_resource_modification_reject" },
    { 0xd9, "esm_information_request" }, { 0xda, "esm_information_response" }, { 0xdb, "notification" },
    { 0xe8, "esm_status" }, { 0, NULL } };
/* EMM causes (TS 24.301 9.9.3.9) and ESM causes (9.9.4.4) that come up in practice; others print as the number */
static const nas_name_t EMM_CAUSE[] = {
    { 2, "imsi_unknown_in_hss" }, { 3, "illegal_ue" }, { 5, "imei_not_accepted" }, { 6, "illegal_me" },
    { 7, "eps_services_not_allowed" }, { 8, "eps_and_non_eps_services_not_allowed" },
    { 9, "ue_identity_cannot_be_derived" }, { 10, "implicitly_detached" }, { 11, "plmn_not_allowed" },
    { 12, "tracking_area_not_allowed" }, { 13, "roaming_not_allowed_in_this_ta" },
    { 14, "eps_services_not_allowed_in_this_plmn" }, { 15, "no_suitable_cells_in_ta" },
    { 16, "msc_temporarily_not_reachable" }, { 17, "network_failure" }, { 18, "cs_domain_not_available" },
    { 19, "esm_failure" }, { 20, "mac_failure" }, { 21, "synch_failure" }, { 22, "congestion" },
    { 35, "requested_service_option_not_authorized" }, { 39, "cs_service_temporarily_not_available" },
    { 40, "no_eps_bearer_context_activated" }, { 42, "severe_network_failure" }, { 111, "protocol_error" }, { 0, NULL } };
static const nas_name_t ESM_CAUSE[] = {
    { 8, "operator_determined_barring" }, { 26, "insufficient_resources" }, { 27, "missing_or_unknown_apn" },
    { 28, "unknown_pdn_type" }, { 29, "user_authentication_failed" }, { 30, "rejected_by_gateway" },
    { 31, "request_rejected_unspecified" }, { 32, "service_option_not_supported" },
    { 33, "service_option_not_subscribed" }, { 34, "service_option_temporarily_out_of_order" },
    { 36, "regular_deactivation" }, { 38, "network_failure" }, { 39, "reactivation_requested" },
    { 54, "pdn_connection_does_not_exist" }, { 55, "multiple_pdn_connections_not_allowed" },
    { 65, "maximum_number_of_eps_bearers_reached" }, { 111, "protocol_error" }, { 0, NULL } };

static const char *nas_name(const nas_name_t *t, int v)
{
    for (; t->n; t++)
        if (t->t == v) return t->n;
    return NULL;
}

/* one NAS message -> event=nas;dir=dl|ul;msg=...[;type=...][;cause=<n>:<name>]; dl = from the network */
static void mob_nas(mobility_t *m, double mts, const uint8_t *b, int len, int dl)
{
    if (len < 6) return;
    const uint8_t *p = b + 4;
    int n = len - 4, pd = p[0] & 15, sh = p[0] >> 4;
    if (pd == 7 && sh >= 1 && sh <= 4) {  /* integrity protected: 4 bytes MAC + sequence number, then the plain message */
        if (n < 8) return;
        p += 6; n -= 6; pd = p[0] & 15; sh = p[0] >> 4;
    }
    const char *name = NULL, *cause = NULL;
    char unk[32], ex[96] = "", cb[64];
    int cv = -1, rej = 0;
    if (pd == 7 && sh == 12) name = "service_request";  /* short format, no message type */
    else if (pd == 7 && sh == 0 && n >= 2) {
        int mt = p[1];
        name = nas_name(NAS_EMM, mt);
        if ((mt == 0x44 || mt == 0x4b || mt == 0x4e) && n >= 3) { cv = p[2]; rej = 1; }  /* attach / TAU / service reject */
        else if (mt == 0x45 && n >= 3) {
            int ty = p[2] & 7;
            if (dl) {  /* network-initiated detach: type, then optionally an EMM cause (IEI 0x53) */
                static const char *T[4] = { "NA", "reattach_required", "reattach_not_required", "imsi_detach" };
                snprintf(ex, sizeof(ex), ";type=%s", ty < 4 ? T[ty] : "NA");
                if (n >= 5 && p[3] == 0x53) cv = p[4];
                rej = 1;
            } else {
                static const char *T[4] = { "NA", "eps", "imsi", "combined" };
                snprintf(ex, sizeof(ex), ";type=%s;switch_off=%d", ty < 4 ? T[ty] : "NA", (p[2] >> 3) & 1);
            }
        } else if (mt == 0x48 && n >= 3) {
            static const char *T[4] = { "ta_updating", "combined", "combined_imsi_attach", "periodic" };
            snprintf(ex, sizeof(ex), ";type=%s", (p[2] & 7) < 4 ? T[p[2] & 7] : "NA");
        } else if (mt == 0x41 && n >= 3) {
            int ty = p[2] & 7;
            snprintf(ex, sizeof(ex), ";type=%s", ty == 1 ? "eps" : ty == 2 ? "combined" : ty == 6 ? "emergency" : "NA");
        }
        if (!name) { snprintf(unk, sizeof(unk), "emm_0x%02x", mt); name = unk; }
        if (cv >= 0) cause = nas_name(EMM_CAUSE, cv);
    } else if (pd == 2 && n >= 3) {  /* ESM: bearer identity / PTI / message type */
        int mt = p[2];
        name = nas_name(NAS_ESM, mt);
        if ((mt == 0xc3 || mt == 0xc7 || mt == 0xcb || mt == 0xcd || mt == 0xd1 || mt == 0xd3 || mt == 0xd5 || mt == 0xd7 ||
             mt == 0xe8) && n >= 4) {
            cv = p[3];
            cause = nas_name(ESM_CAUSE, cv);
        }
        if (!name) { snprintf(unk, sizeof(unk), "esm_0x%02x", mt); name = unk; }
    } else
        return;
    if (cv >= 0) {
        snprintf(cb, sizeof(cb), ";cause=%d:%s", cv, cause ? cause : "other");
        size_t l = strlen(ex);
        snprintf(ex + l, sizeof(ex) - l, "%s", cb);
    }
    if (rej) m->counts[MOB_NAS_REJ]++;
    mob_ev(m, mts, "event=nas;dir=%s;msg=%s%s", dl ? "dl" : "ul", name, ex);
}

#endif
