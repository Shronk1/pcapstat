/**
 * @file anomaly.c
 * @brief Implementation of rule-based network anomaly detection engine.
 */

#include "anomaly.h"
#include "parser.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int anomaly_list_init(anomaly_list_t *list)
{
    if (list == NULL)
        return PCAPSTAT_ERR_ARGS;

    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
    return PCAPSTAT_OK;
}

int anomaly_list_append(anomaly_list_t *list, const anomaly_t *item)
{
    if (list == NULL || item == NULL)
        return PCAPSTAT_ERR_ARGS;

    if (list->count >= list->capacity) {
        size_t new_cap = (list->capacity == 0) ? 8 : list->capacity * 2;
        anomaly_t *new_items =
            (anomaly_t *)realloc(list->items, new_cap * sizeof(anomaly_t));
        if (new_items == NULL)
            return PCAPSTAT_ERR_NOMEM;

        list->items = new_items;
        list->capacity = new_cap;
    }

    list->items[list->count++] = *item;
    return PCAPSTAT_OK;
}

void anomaly_list_free(anomaly_list_t *list)
{
    if (list == NULL)
        return;

    free(list->items);
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

const char *anomaly_severity_str(anomaly_severity_t severity)
{
    switch (severity) {
    case ANOMALY_CRITICAL:
        return "CRITICAL";
    case ANOMALY_WARNING:
        return "WARNING";
    case ANOMALY_INFO:
        return "INFO";
    default:
        return "UNKNOWN";
    }
}

/**
 * @brief Deterministic comparator for qsort:
 *        CRITICAL (2) -> WARNING (1) -> INFO (0),
 *        then category ASC, subject ASC, description ASC.
 */
static int compare_anomaly(const void *a, const void *b)
{
    const anomaly_t *x = (const anomaly_t *)a;
    const anomaly_t *y = (const anomaly_t *)b;

    /* Severity descending */
    if (x->severity > y->severity)
        return -1;
    if (x->severity < y->severity)
        return 1;

    /* Primary tie-breaker: category */
    int cat_cmp = strcmp(x->category, y->category);
    if (cat_cmp != 0)
        return cat_cmp;

    /* Secondary tie-breaker: subject */
    int subj_cmp = strcmp(x->subject, y->subject);
    if (subj_cmp != 0)
        return subj_cmp;

    /* Tertiary tie-breaker: description */
    return strcmp(x->description, y->description);
}

/* -------------------------------------------------------------------
 * UDP burst helpers (rule 6)
 * ------------------------------------------------------------------- */

/** One flagged one-second bucket, collected before runs are merged. */
typedef struct {
    int64_t  sec;         /**< Epoch second of the bucket. */
    uint64_t udp_packets; /**< UDP packets in that second. */
    double   baseline;    /**< Leave-one-out baseline used for the check. */
} udp_burst_sec_t;

/**
 * Leave-one-out UDP baseline for a bucket holding @p b of @p udp_total
 * UDP packets spread over @p n active seconds: the mean of the *other*
 * n - 1 seconds, so the burst cannot inflate its own threshold. Only
 * called with n >= 2 (a single active second has no baseline and is never
 * flagged, see detect_udp_bursts()); returns 0 defensively otherwise.
 */
static double udp_leave_one_out_baseline(uint64_t udp_total, uint64_t b,
                                         size_t n)
{
    if (n < 2 || b > udp_total)
        return 0.0;
    return (double)(udp_total - b) / (double)(n - 1);
}

static bool udp_second_is_burst(uint64_t b, double baseline,
                                const anomaly_thresholds_t *thresholds)
{
    return b >= thresholds->udp_burst_min &&
           (double)b > thresholds->udp_burst_mult * baseline;
}

static int compare_udp_burst_sec(const void *left, const void *right)
{
    const udp_burst_sec_t *x = (const udp_burst_sec_t *)left;
    const udp_burst_sec_t *y = (const udp_burst_sec_t *)right;
    if (x->sec < y->sec)
        return -1;
    if (x->sec > y->sec)
        return 1;
    return 0;
}

/**
 * Format an epoch second as "YYYY-MM-DD HH:MM:SS UTC". Falls back to
 * "Epoch N s" when the year does not fit struct tm (kept short so it fits
 * the report's subject column).
 */
static void format_utc_second(int64_t sec, char *buf, size_t len)
{
    time_t t = (time_t)sec;
    struct tm tm;
    if ((int64_t)t == sec && gmtime_r(&t, &tm) != NULL &&
        strftime(buf, len, "%Y-%m-%d %H:%M:%S UTC", &tm) > 0)
        return;
    snprintf(buf, len, "Epoch %" PRId64 " s", sec);
}

/**
 * Append one "UDP Burst" finding for @p len consecutive flagged seconds
 * starting at @p run (sorted by second, len >= 1).
 */
static int append_udp_burst_run(const udp_burst_sec_t *run, size_t len,
                                const anomaly_thresholds_t *thresholds,
                                anomaly_list_t *out)
{
    size_t peak = 0;
    uint64_t total = 0;
    for (size_t i = 0; i < len; ++i) {
        total += run[i].udp_packets;
        if (run[i].udp_packets > run[peak].udp_packets)
            peak = i;
    }

    anomaly_t a;
    memset(&a, 0, sizeof(a));
    a.severity = ANOMALY_WARNING;
    snprintf(a.category, sizeof(a.category), "UDP Burst");
    format_utc_second(run[0].sec, a.subject, sizeof(a.subject));
    snprintf(a.description, sizeof(a.description),
             "Burst lasted %zu s (%" PRIu64 " UDP pkts): peak %" PRIu64
             " pkt/s vs. baseline %.1f pkt/s (mean of the other active"
             " seconds); thresholds: > %.1fx baseline and >= %" PRIu32
             " pkt/s",
             len, total, run[peak].udp_packets, run[peak].baseline,
             thresholds->udp_burst_mult, thresholds->udp_burst_min);
    return anomaly_list_append(out, &a);
}

/**
 * Rule 6: flag one-second buckets whose UDP count reaches the absolute
 * minimum and exceeds the multiplier times the leave-one-out baseline,
 * then report each run of consecutive flagged seconds as one finding.
 */
static int detect_udp_bursts(const stats_ctx_t *stats,
                             const anomaly_thresholds_t *thresholds,
                             anomaly_list_t *out)
{
    if (stats->ts_buckets_ht == NULL)
        return PCAPSTAT_OK;
    const size_t n = ht_count(stats->ts_buckets_ht);
    /* Owner decision (FIX-06): with fewer than two active seconds there is
     * no baseline to compare against, so nothing is flagged. */
    if (n < 2)
        return PCAPSTAT_OK;

    const void *key;
    size_t key_len;
    void *val;

    /* Pass 1: UDP total over the buckets (packets without a usable
     * timestamp are in no bucket, so stats->udp_packets may be larger). */
    uint64_t udp_total = 0;
    ht_iter_t it = ht_iter_begin(stats->ts_buckets_ht);
    while (ht_iter_next(&it, &key, &key_len, &val))
        udp_total += ((const ts_bucket_t *)val)->udp_packets;
    if (udp_total == 0)
        return PCAPSTAT_OK;

    /* Pass 2: count flagged seconds so the scratch array is exact. */
    size_t flagged = 0;
    it = ht_iter_begin(stats->ts_buckets_ht);
    while (ht_iter_next(&it, &key, &key_len, &val)) {
        const ts_bucket_t *b = (const ts_bucket_t *)val;
        double base = udp_leave_one_out_baseline(udp_total, b->udp_packets, n);
        if (udp_second_is_burst(b->udp_packets, base, thresholds))
            flagged++;
    }
    if (flagged == 0)
        return PCAPSTAT_OK;

    int rc = PCAPSTAT_OK;
    udp_burst_sec_t *secs =
        (udp_burst_sec_t *)malloc(flagged * sizeof(*secs));
    if (secs == NULL)
        return PCAPSTAT_ERR_NOMEM;

    /* Pass 3: collect flagged seconds. */
    size_t count = 0;
    it = ht_iter_begin(stats->ts_buckets_ht);
    while (count < flagged && ht_iter_next(&it, &key, &key_len, &val)) {
        const ts_bucket_t *b = (const ts_bucket_t *)val;
        double base = udp_leave_one_out_baseline(udp_total, b->udp_packets, n);
        if (udp_second_is_burst(b->udp_packets, base, thresholds)) {
            secs[count].sec = b->sec;
            secs[count].udp_packets = b->udp_packets;
            secs[count].baseline = base;
            count++;
        }
    }
    qsort(secs, count, sizeof(*secs), compare_udp_burst_sec);

    /* Merge runs of consecutive seconds. Sorted and distinct, so
     * secs[i - 1].sec < secs[i].sec and the + 1 cannot overflow. */
    size_t run_start = 0;
    for (size_t i = 1; i <= count; ++i) {
        if (i < count && secs[i].sec == secs[i - 1].sec + 1)
            continue;
        rc = append_udp_burst_run(&secs[run_start], i - run_start,
                                  thresholds, out);
        if (rc != PCAPSTAT_OK)
            goto cleanup;
        run_start = i;
    }

cleanup:
    free(secs);
    return rc;
}

int anomaly_detect(const stats_ctx_t *stats,
                   const anomaly_thresholds_t *thresholds,
                   anomaly_list_t *out)
{
    if (stats == NULL || out == NULL)
        return PCAPSTAT_ERR_ARGS;

    anomaly_thresholds_t def_thresh = ANOMALY_THRESHOLDS_DEFAULT;
    if (thresholds == NULL)
        thresholds = &def_thresh;

    int rc = PCAPSTAT_OK;
    anomaly_t a;

    /* -----------------------------------------------------------------
     * 1. Port Scan: host targeted >= N unique destination ports
     * ----------------------------------------------------------------- */
    if (stats->hosts_ht != NULL) {
        ht_iter_t it = ht_iter_begin(stats->hosts_ht);
        const void *key;
        size_t key_len;
        void *val;
        while (ht_iter_next(&it, &key, &key_len, &val)) {
            const host_stats_t *h = (const host_stats_t *)val;
            if (h->unique_dst_ports >= thresholds->portscan_threshold) {
                memset(&a, 0, sizeof(a));
                a.severity = ANOMALY_CRITICAL;
                snprintf(a.category, sizeof(a.category), "Port Scan");
                parser_format_ip(h->ip_version, h->ip, a.subject,
                                 sizeof(a.subject));
                snprintf(a.description, sizeof(a.description),
                         "Host scanned %" PRIu32
                         " unique destination ports (threshold: %" PRIu32 ")",
                         h->unique_dst_ports, thresholds->portscan_threshold);
                rc = anomaly_list_append(out, &a);
                if (rc != PCAPSTAT_OK)
                    return rc;
            }
        }
    }

    /* -----------------------------------------------------------------
     * 2. SYN Flood / Incomplete Handshakes:
     *    High SYN count (>= 50) with SYN to SYN-ACK ratio > 3.0.
     *    A host that also meets the port-scan threshold is reported only
     *    as a Port Scan (rule 1): its unanswered SYNs are the probes.
     *    host_syn_flood is set either way (the SYN excess is attributed
     *    to a host), so the global fallback below behaves as before.
     * ----------------------------------------------------------------- */
    bool host_syn_flood = false;
    if (stats->hosts_ht != NULL) {
        ht_iter_t it = ht_iter_begin(stats->hosts_ht);
        const void *key;
        size_t key_len;
        void *val;
        while (ht_iter_next(&it, &key, &key_len, &val)) {
            const host_stats_t *h = (const host_stats_t *)val;
            if (h->syn_sent >= thresholds->syn_flood_min) {
                double ratio = (h->syn_ack_recv == 0)
                                   ? (double)h->syn_sent
                                   : ((double)h->syn_sent /
                                      (double)h->syn_ack_recv);
                if (ratio > thresholds->syn_ratio) {
                    host_syn_flood = true;
                    if (h->unique_dst_ports >= thresholds->portscan_threshold)
                        continue; /* already reported by rule 1 */
                    memset(&a, 0, sizeof(a));
                    a.severity = ANOMALY_CRITICAL;
                    snprintf(a.category, sizeof(a.category), "SYN Flood");
                    parser_format_ip(h->ip_version, h->ip, a.subject,
                                     sizeof(a.subject));
                    snprintf(a.description, sizeof(a.description),
                             "Host sent %" PRIu64 " SYNs with only %" PRIu64
                             " SYN-ACKs received (ratio: %.2f > %.2f)",
                             h->syn_sent, h->syn_ack_recv, ratio,
                             thresholds->syn_ratio);
                    rc = anomaly_list_append(out, &a);
                    if (rc != PCAPSTAT_OK)
                        return rc;
                }
            }
        }
    }
    if (!host_syn_flood && stats->syn >= thresholds->syn_flood_min) {
        double ratio = (stats->syn_ack == 0)
                           ? (double)stats->syn
                           : ((double)stats->syn / (double)stats->syn_ack);
        if (ratio > thresholds->syn_ratio) {
            memset(&a, 0, sizeof(a));
            a.severity = ANOMALY_CRITICAL;
            snprintf(a.category, sizeof(a.category), "SYN Flood");
            snprintf(a.subject, sizeof(a.subject), "Global");
            snprintf(a.description, sizeof(a.description),
                     "Global SYN count of %" PRIu64 " with only %" PRIu64
                     " SYN-ACKs received (ratio: %.2f > %.2f)",
                     stats->syn, stats->syn_ack, ratio, thresholds->syn_ratio);
            rc = anomaly_list_append(out, &a);
            if (rc != PCAPSTAT_OK)
                return rc;
        }
    }

    /* -----------------------------------------------------------------
     * 3. Elevated TCP Retransmissions:
     *    Retransmission rate > 5% per flow (min. 20 TCP pkts) or globally
     * ----------------------------------------------------------------- */
    uint64_t total_retrans = 0;
    bool flow_retrans_flagged = false;
    if (stats->flows_ht != NULL) {
        ht_iter_t it = ht_iter_begin(stats->flows_ht);
        const void *key;
        size_t key_len;
        void *val;
        while (ht_iter_next(&it, &key, &key_len, &val)) {
            const flow_stats_t *f = (const flow_stats_t *)val;
            total_retrans += f->retransmissions;
            if (f->proto == IPPROTO_TCP && f->packets >= 20) {
                double rate =
                    ((double)f->retransmissions / (double)f->packets) * 100.0;
                if (rate > thresholds->retrans_pct) {
                    memset(&a, 0, sizeof(a));
                    a.severity = ANOMALY_WARNING;
                    snprintf(a.category, sizeof(a.category),
                             "TCP Retransmissions");
                    char sip[46], dip[46];
                    parser_format_ip(f->ip_version, f->src_ip, sip,
                                     sizeof(sip));
                    parser_format_ip(f->ip_version, f->dst_ip, dip,
                                     sizeof(dip));
                    snprintf(a.subject, sizeof(a.subject),
                             "%s:%u -> %s:%u (TCP)", sip, f->src_port, dip,
                             f->dst_port);
                    snprintf(a.description, sizeof(a.description),
                             "Flow retransmission rate is %.2f%% (%" PRIu64
                             " / %" PRIu64 " pkts, threshold: %.1f%%)",
                             rate, f->retransmissions, f->packets,
                             thresholds->retrans_pct);
                    rc = anomaly_list_append(out, &a);
                    if (rc != PCAPSTAT_OK)
                        return rc;
                    flow_retrans_flagged = true;
                }
            }
        }
    }
    if (!flow_retrans_flagged && stats->tcp_packets >= 20) {
        double global_rate =
            ((double)total_retrans / (double)stats->tcp_packets) * 100.0;
        if (global_rate > thresholds->retrans_pct) {
            memset(&a, 0, sizeof(a));
            a.severity = ANOMALY_WARNING;
            snprintf(a.category, sizeof(a.category), "TCP Retransmissions");
            snprintf(a.subject, sizeof(a.subject), "Global");
            snprintf(a.description, sizeof(a.description),
                     "Global TCP retransmission rate is %.2f%% (%" PRIu64
                     " / %" PRIu64 " pkts, threshold: %.1f%%)",
                     global_rate, total_retrans, stats->tcp_packets,
                     thresholds->retrans_pct);
            rc = anomaly_list_append(out, &a);
            if (rc != PCAPSTAT_OK)
                return rc;
        }
    }

    /* -----------------------------------------------------------------
     * 4. RST Spike: RST packets exceed > 10% of TCP traffic (min 30 pkts)
     * ----------------------------------------------------------------- */
    if (stats->tcp_packets >= 30) {
        double rst_rate =
            ((double)stats->rst / (double)stats->tcp_packets) * 100.0;
        if (rst_rate > thresholds->rst_pct) {
            memset(&a, 0, sizeof(a));
            a.severity = ANOMALY_WARNING;
            snprintf(a.category, sizeof(a.category), "RST Spike");
            snprintf(a.subject, sizeof(a.subject), "Global");
            snprintf(a.description, sizeof(a.description),
                     "RST packet rate is %.2f%% of TCP traffic (%" PRIu64
                     " / %" PRIu64 " pkts, threshold: %.1f%%)",
                     rst_rate, stats->rst, stats->tcp_packets,
                     thresholds->rst_pct);
            rc = anomaly_list_append(out, &a);
            if (rc != PCAPSTAT_OK)
                return rc;
        }
    }

    /* -----------------------------------------------------------------
     * 5. Suspicious TCP Flags:
     *    Null Scan, Xmas Scan, SYN+FIN, or SYN+RST packets
     * ----------------------------------------------------------------- */
    if (stats->null_scan_pkts > 0) {
        memset(&a, 0, sizeof(a));
        a.severity = ANOMALY_CRITICAL;
        snprintf(a.category, sizeof(a.category), "Suspicious TCP Flags");
        snprintf(a.subject, sizeof(a.subject), "Null Scan");
        snprintf(a.description, sizeof(a.description),
                 "Detected %" PRIu64 " Null Scan packet(s) (no TCP flags set)",
                 stats->null_scan_pkts);
        rc = anomaly_list_append(out, &a);
        if (rc != PCAPSTAT_OK)
            return rc;
    }
    if (stats->xmas_scan_pkts > 0) {
        memset(&a, 0, sizeof(a));
        a.severity = ANOMALY_CRITICAL;
        snprintf(a.category, sizeof(a.category), "Suspicious TCP Flags");
        snprintf(a.subject, sizeof(a.subject), "Xmas Scan");
        snprintf(a.description, sizeof(a.description),
                 "Detected %" PRIu64
                 " Xmas Scan packet(s) (FIN+PSH+URG flags set)",
                 stats->xmas_scan_pkts);
        rc = anomaly_list_append(out, &a);
        if (rc != PCAPSTAT_OK)
            return rc;
    }
    if (stats->syn_fin_pkts > 0) {
        memset(&a, 0, sizeof(a));
        a.severity = ANOMALY_CRITICAL;
        snprintf(a.category, sizeof(a.category), "Suspicious TCP Flags");
        snprintf(a.subject, sizeof(a.subject), "SYN+FIN");
        snprintf(a.description, sizeof(a.description),
                 "Detected %" PRIu64
                 " packet(s) with conflicting SYN+FIN flags set",
                 stats->syn_fin_pkts);
        rc = anomaly_list_append(out, &a);
        if (rc != PCAPSTAT_OK)
            return rc;
    }
    if (stats->syn_rst_pkts > 0) {
        memset(&a, 0, sizeof(a));
        a.severity = ANOMALY_CRITICAL;
        snprintf(a.category, sizeof(a.category), "Suspicious TCP Flags");
        snprintf(a.subject, sizeof(a.subject), "SYN+RST");
        snprintf(a.description, sizeof(a.description),
                 "Detected %" PRIu64
                 " packet(s) with conflicting SYN+RST flags set",
                 stats->syn_rst_pkts);
        rc = anomaly_list_append(out, &a);
        if (rc != PCAPSTAT_OK)
            return rc;
    }

    /* -----------------------------------------------------------------
     * 6. UDP Burst / Flood:
     *    A 1-second bucket with UDP count >= the absolute minimum
     *    (100 pkt/s) and > 3x the leave-one-out baseline (mean of the
     *    other active seconds). Consecutive flagged seconds are merged
     *    into one finding. Needs >= 2 active seconds (no baseline else).
     * ----------------------------------------------------------------- */
    rc = detect_udp_bursts(stats, thresholds, out);
    if (rc != PCAPSTAT_OK)
        return rc;

    /* -----------------------------------------------------------------
     * 7. Malformed / Truncated Packets:
     *    Flag (WARNING) if malformed_packets > 0
     * ----------------------------------------------------------------- */
    if (stats->malformed_packets > 0) {
        memset(&a, 0, sizeof(a));
        a.severity = ANOMALY_WARNING;
        snprintf(a.category, sizeof(a.category), "Malformed Packets");
        snprintf(a.subject, sizeof(a.subject), "Global");
        snprintf(a.description, sizeof(a.description),
                 "Detected %" PRIu64 " malformed or truncated packet(s)",
                 stats->malformed_packets);
        rc = anomaly_list_append(out, &a);
        if (rc != PCAPSTAT_OK)
            return rc;
    }

    /* -----------------------------------------------------------------
     * 8. Capture Integrity:
     *    Flag (WARNING) if any input file stopped on a truncated or
     *    corrupt record (stats->truncated_files, maintained by main).
     * ----------------------------------------------------------------- */
    if (stats->truncated_files > 0) {
        memset(&a, 0, sizeof(a));
        a.severity = ANOMALY_WARNING;
        snprintf(a.category, sizeof(a.category), "Capture Integrity");
        if (stats->files_processed >= stats->truncated_files)
            snprintf(a.subject, sizeof(a.subject),
                     "%" PRIu64 " of %" PRIu64 " file(s)",
                     stats->truncated_files, stats->files_processed);
        else
            snprintf(a.subject, sizeof(a.subject), "%" PRIu64 " file(s)",
                     stats->truncated_files);
        snprintf(a.description, sizeof(a.description),
                 "%" PRIu64 " input file(s) truncated or corrupt; statistics"
                 " cover only the readable part",
                 stats->truncated_files);
        rc = anomaly_list_append(out, &a);
        if (rc != PCAPSTAT_OK)
            return rc;
    }

    /* -----------------------------------------------------------------
     * Sort results by severity: CRITICAL -> WARNING -> INFO
     * ----------------------------------------------------------------- */
    if (out->count > 1) {
        qsort(out->items, out->count, sizeof(anomaly_t), compare_anomaly);
    }

    return PCAPSTAT_OK;
}
