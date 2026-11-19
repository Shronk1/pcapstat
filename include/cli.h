/**
 * @file cli.h
 * @brief CLI argument parser for pcapstat.
 *
 * Parses command-line flags using getopt_long(), supporting one or more
 * .pcap inputs, output directory, anomaly threshold overrides, and
 * informational flags (--help, --version, --verbose).
 *
 * Memory ownership:
 * - cli_parse() allocates @c cfg->input_files (array of strdup'd strings)
 *   and strdup's @c cfg->output_dir.
 * - cli_free() releases all heap memory inside cli_config_t.
 * - The caller must call cli_free() on every cli_config_t passed to
 *   cli_parse(), regardless of the return code (partial allocations are
 *   possible on failure paths).
 */

#ifndef PCAPSTAT_CLI_H
#define PCAPSTAT_CLI_H

#include "common.h"

#include <stdbool.h>
#include <stdio.h>

/**
 * @brief Parsed CLI configuration.
 *
 * All heap pointers are owned by this struct and freed by cli_free().
 */
typedef struct {
    char  **input_files;              /**< Array of input .pcap paths (strdup'd). */
    size_t  input_count;              /**< Number of entries in @c input_files. */
    char   *output_dir;               /**< Output directory (strdup'd; default "./pcapstat_out"). */
    anomaly_thresholds_t thresholds;  /**< Anomaly detection thresholds (defaults from common.h). */
    bool    verbose;                  /**< Enable verbose output. */
    bool    show_help;                /**< User requested --help. */
    bool    show_version;             /**< User requested --version. */
} cli_config_t;

/**
 * @brief Parse command-line arguments into @p cfg.
 *
 * Zero-initializes @p cfg, then parses @c argv using getopt_long().
 * Supports @c -i/--input (repeatable), positional .pcap args after options,
 * @c -o/--output, @c --portscan-threshold, @c -v/--verbose,
 * @c -h/--help, and @c -V/--version.
 *
 * When @c --help or @c --version is encountered, the corresponding flag is
 * set, parsing stops, and @c PCAPSTAT_OK is returned immediately.
 *
 * @param argc  Argument count from main().
 * @param argv  Argument vector from main().
 * @param[out] cfg  Output struct (zeroed and filled by this function).
 * @return @c PCAPSTAT_OK on success,
 *         @c PCAPSTAT_ERR_ARGS on invalid input,
 *         @c PCAPSTAT_ERR_NOMEM on allocation failure.
 */
int cli_parse(int argc, char **argv, cli_config_t *cfg);

/**
 * @brief Validate parsed config and prepare the environment.
 *
 * Checks that at least one input file is specified and readable
 * (@c access(..., R_OK)).  Creates the output directory
 * (@c mkdir(..., 0755), tolerating @c EEXIST).
 *
 * @param cfg  Parsed configuration (not modified).
 * @return @c PCAPSTAT_OK on success,
 *         @c PCAPSTAT_ERR_ARGS if no inputs or a file is unreadable,
 *         @c PCAPSTAT_ERR_IO if the output directory cannot be created.
 */
int cli_validate_and_prepare(const cli_config_t *cfg);

/**
 * @brief Print usage/help message to @p stream.
 *
 * @param stream     Output stream (typically stdout or stderr).
 * @param prog_name  Program name (usually argv[0]).
 */
void cli_print_usage(FILE *stream, const char *prog_name);

/**
 * @brief Free all heap memory owned by @p cfg.
 *
 * Safe to call on a zero-initialized or partially-parsed cli_config_t.
 * Sets internal pointers to NULL after freeing.
 *
 * @param cfg  Configuration to free (may be NULL — no-op).
 */
void cli_free(cli_config_t *cfg);

#endif /* PCAPSTAT_CLI_H */
