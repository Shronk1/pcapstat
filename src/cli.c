/**
 * @file cli.c
 * @brief CLI argument parser implementation for pcapstat.
 */

#include "cli.h"

#include <errno.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/** @brief Default output directory when -o is not specified. */
#define DEFAULT_OUTPUT_DIR "./pcapstat_out"

/** @brief Long-only option ID for --portscan-threshold (above ASCII range). */
enum { OPT_PORTSCAN_THRESHOLD = 256 };

/**
 * Append a strdup'd copy of @p path to cfg->input_files.
 * Grows the array by one slot via realloc on each call.
 */
static int add_input_file(cli_config_t *cfg, const char *path)
{
    if (cfg->input_count >= PCAPSTAT_MAX_INPUT_FILES) {
        fprintf(stderr, "pcapstat: too many input files (max %d)\n",
                PCAPSTAT_MAX_INPUT_FILES);
        return PCAPSTAT_ERR_ARGS;
    }

    char **arr = realloc(cfg->input_files,
                         (cfg->input_count + 1) * sizeof(char *));
    if (!arr)
        return PCAPSTAT_ERR_NOMEM;
    cfg->input_files = arr;

    cfg->input_files[cfg->input_count] = strdup(path);
    if (!cfg->input_files[cfg->input_count])
        return PCAPSTAT_ERR_NOMEM;

    cfg->input_count++;
    return PCAPSTAT_OK;
}

int cli_parse(int argc, char **argv, cli_config_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->thresholds = (anomaly_thresholds_t)ANOMALY_THRESHOLDS_DEFAULT;

    /* Reset glibc getopt state so the function is reentrant across calls
       (required for unit tests that invoke cli_parse multiple times). */
    optind = 0;

    static const struct option long_options[] = {
        { "input",              required_argument, NULL, 'i'                    },
        { "output",             required_argument, NULL, 'o'                    },
        { "portscan-threshold", required_argument, NULL, OPT_PORTSCAN_THRESHOLD},
        { "verbose",            no_argument,       NULL, 'v'                    },
        { "help",               no_argument,       NULL, 'h'                    },
        { "version",            no_argument,       NULL, 'V'                    },
        { NULL, 0, NULL, 0 }
    };

    int opt;
    int rc;

    while ((opt = getopt_long(argc, argv, "i:o:vhV", long_options, NULL)) != -1) {
        switch (opt) {
        case 'i':
            rc = add_input_file(cfg, optarg);
            if (rc != PCAPSTAT_OK)
                return rc;
            break;

        case 'o':
            free(cfg->output_dir);
            cfg->output_dir = strdup(optarg);
            if (!cfg->output_dir)
                return PCAPSTAT_ERR_NOMEM;
            break;

        case OPT_PORTSCAN_THRESHOLD: {
            char *endptr;
            errno = 0;
            long val = strtol(optarg, &endptr, 10);
            if (errno != 0 || endptr == optarg || *endptr != '\0' ||
                val <= 0 || (unsigned long)val > UINT32_MAX) {
                fprintf(stderr,
                        "%s: invalid --portscan-threshold value: '%s'\n",
                        argv[0], optarg);
                return PCAPSTAT_ERR_ARGS;
            }
            cfg->thresholds.portscan_threshold = (uint32_t)val;
            break;
        }

        case 'v':
            cfg->verbose = true;
            break;

        case 'h':
            cfg->show_help = true;
            return PCAPSTAT_OK;

        case 'V':
            cfg->show_version = true;
            return PCAPSTAT_OK;

        default: /* '?' — unknown or malformed option */
            return PCAPSTAT_ERR_ARGS;
        }
    }

    /* Collect remaining positional arguments as additional input files. */
    for (int i = optind; i < argc; i++) {
        rc = add_input_file(cfg, argv[i]);
        if (rc != PCAPSTAT_OK)
            return rc;
    }

    /* Apply default output directory if not overridden by -o. */
    if (!cfg->output_dir) {
        cfg->output_dir = strdup(DEFAULT_OUTPUT_DIR);
        if (!cfg->output_dir)
            return PCAPSTAT_ERR_NOMEM;
    }

    return PCAPSTAT_OK;
}

int cli_validate_and_prepare(const cli_config_t *cfg)
{
    if (cfg->input_count == 0) {
        fprintf(stderr, "pcapstat: no input files specified\n");
        return PCAPSTAT_ERR_ARGS;
    }

    for (size_t i = 0; i < cfg->input_count; i++) {
        if (access(cfg->input_files[i], R_OK) != 0) {
            fprintf(stderr, "pcapstat: cannot read input file '%s': %s\n",
                    cfg->input_files[i], strerror(errno));
            return PCAPSTAT_ERR_ARGS;
        }
    }

    if (mkdir(cfg->output_dir, 0755) != 0 && errno != EEXIST) {
        fprintf(stderr,
                "pcapstat: cannot create output directory '%s': %s\n",
                cfg->output_dir, strerror(errno));
        return PCAPSTAT_ERR_IO;
    }

    return PCAPSTAT_OK;
}

void cli_print_usage(FILE *stream, const char *prog_name)
{
    fprintf(stream,
            "Usage: %s [OPTIONS] [FILE...]\n"
            "\n"
            "Analyze TCP/UDP traffic from .pcap files and generate\n"
            "PNG charts plus a multi-page PDF report.\n"
            "\n"
            "Options:\n"
            "  -i, --input <file.pcap>        Input pcap file (repeatable)\n"
            "  -o, --output <dir>             Output directory"
            " (default: " DEFAULT_OUTPUT_DIR ")\n"
            "      --portscan-threshold <N>   Unique dst-port count for"
            " port-scan detection\n"
            "                                 (default: %u)\n"
            "  -v, --verbose                  Enable verbose output\n"
            "  -h, --help                     Show this help message\n"
            "  -V, --version                  Show version information\n"
            "\n"
            "Positional arguments are treated as additional input files.\n",
            prog_name, DEFAULT_PORTSCAN_THRESHOLD);
}

void cli_free(cli_config_t *cfg)
{
    if (!cfg)
        return;

    for (size_t i = 0; i < cfg->input_count; i++)
        free(cfg->input_files[i]);
    free(cfg->input_files);
    free(cfg->output_dir);

    memset(cfg, 0, sizeof(*cfg));
}
