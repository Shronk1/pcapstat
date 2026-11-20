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
     *    High SYN count (>= 50) with SYN to SYN-ACK ratio > 3.0
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
                    host_syn_flood = true;
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
     *    Any 1-second window where UDP packet count exceeds 3x the mean
     *    and an absolute minimum (>= 100 pkt/s)
     * ----------------------------------------------------------------- */
    size_t num_buckets = 0;
    if (stats->ts_buckets_ht != NULL)
        num_buckets = ht_count(stats->ts_buckets_ht);
    else if (stats->timeline != NULL)
        num_buckets = stats->timeline_count;

    if (num_buckets > 0 && stats->udp_packets > 0) {
        double mean_udp = (double)stats->udp_packets / (double)num_buckets;
        double burst_thresh = thresholds->udp_burst_mult * mean_udp;

        if (stats->ts_buckets_ht != NULL && ht_count(stats->ts_buckets_ht) > 0) {
            ht_iter_t it = ht_iter_begin(stats->ts_buckets_ht);
            const void *key;
            size_t key_len;
            void *val;
            while (ht_iter_next(&it, &key, &key_len, &val)) {
                const ts_bucket_t *b = (const ts_bucket_t *)val;
                if (b->udp_packets >= thresholds->udp_burst_min &&
                    (double)b->udp_packets > burst_thresh) {
                    memset(&a, 0, sizeof(a));
                    a.severity = ANOMALY_WARNING;
                    snprintf(a.category, sizeof(a.category), "UDP Burst");
                    snprintf(a.subject, sizeof(a.subject),
                             "Second %" PRId64, b->sec);
                    snprintf(a.description, sizeof(a.description),
                             "UDP burst of %" PRIu64
                             " pkt/s exceeds %.1fx mean (%.1f pkt/s, min: %" PRIu32
                             " pkt/s)",
                             b->udp_packets, thresholds->udp_burst_mult,
                             mean_udp, thresholds->udp_burst_min);
                    rc = anomaly_list_append(out, &a);
                    if (rc != PCAPSTAT_OK)
                        return rc;
                }
            }
        } else if (stats->timeline != NULL) {
            for (size_t i = 0; i < stats->timeline_count; ++i) {
                const ts_bucket_t *b = &stats->timeline[i];
                uint64_t peak = b->udp_packets_max > 0 ? b->udp_packets_max
                                                       : b->udp_packets;
                if (peak >= thresholds->udp_burst_min &&
                    (double)peak > burst_thresh) {
                    memset(&a, 0, sizeof(a));
                    a.severity = ANOMALY_WARNING;
                    snprintf(a.category, sizeof(a.category), "UDP Burst");
                    snprintf(a.subject, sizeof(a.subject),
                             "Second %" PRId64, b->sec);
                    snprintf(a.description, sizeof(a.description),
                             "UDP burst of %" PRIu64
                             " pkt/s exceeds %.1fx mean (%.1f pkt/s, min: %" PRIu32
                             " pkt/s)",
                             peak, thresholds->udp_burst_mult, mean_udp,
                             thresholds->udp_burst_min);
                    rc = anomaly_list_append(out, &a);
                    if (rc != PCAPSTAT_OK)
                        return rc;
                }
            }
        }
    }

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
     * Sort results by severity: CRITICAL -> WARNING -> INFO
     * ----------------------------------------------------------------- */
    if (out->count > 1) {
        qsort(out->items, out->count, sizeof(anomaly_t), compare_anomaly);
    }

    return PCAPSTAT_OK;
}
