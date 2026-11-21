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

/**
 * Remove input_files[idx] (freeing it) and shift the tail down by one.
 */
static void remove_input_file(cli_config_t *cfg, size_t idx)
{
    free(cfg->input_files[idx]);
    for (size_t j = idx + 1; j < cfg->input_count; j++)
        cfg->input_files[j - 1] = cfg->input_files[j];
    cfg->input_count--;
    cfg->input_files[cfg->input_count] = NULL;
}

/**
 * Drop inputs that name the same file as an earlier input (same device and
 * inode, i.e. the same realpath(), also through symlinks or hard links).
 * Merging a file with itself would double every counter and fabricate
 * findings. Prints one warning per skipped duplicate.
 */
static int skip_duplicate_inputs(cli_config_t *cfg)
{
    size_t i = 0;
    while (i < cfg->input_count) {
        struct stat st_i;
        if (stat(cfg->input_files[i], &st_i) != 0) {
            fprintf(stderr, "pcapstat: cannot stat input file '%s': %s\n",
                    cfg->input_files[i], strerror(errno));
            return PCAPSTAT_ERR_ARGS;
        }

        size_t dup_of = i;
        for (size_t k = 0; k < i; k++) {
            struct stat st_k;
            if (stat(cfg->input_files[k], &st_k) == 0 &&
                st_k.st_dev == st_i.st_dev && st_k.st_ino == st_i.st_ino) {
                dup_of = k;
                break;
            }
        }
        if (dup_of == i) {
            i++;
            continue;
        }
        fprintf(stderr,
                "pcapstat: warning: skipping duplicate input '%s' (same file"
                " as '%s')\n",
                cfg->input_files[i], cfg->input_files[dup_of]);
        remove_input_file(cfg, i);
    }
    return PCAPSTAT_OK;
}

/**
 * mkdir -p: create @p path and every missing parent with mode 0755.
 * Existing components are accepted only if they are directories.
 */
static int make_dirs(const char *path)
{
    size_t len = strlen(path);
    char *buf = malloc(len + 1);
    int rc = PCAPSTAT_OK;

    if (!buf)
        return PCAPSTAT_ERR_NOMEM;
    memcpy(buf, path, len + 1);

    /* Create each prefix ending before a '/' (skipping the root and
     * repeated slashes), then the full path. */
    for (size_t i = 1; i <= len; i++) {
        if (i < len && (buf[i] != '/' || buf[i - 1] == '/'))
            continue;
        char saved = buf[i];
        buf[i] = '\0';
        if (mkdir(buf, 0755) != 0 && errno != EEXIST) {
            fprintf(stderr,
                    "pcapstat: cannot create output directory '%s': %s\n",
                    buf, strerror(errno));
            rc = PCAPSTAT_ERR_IO;
            goto cleanup;
        }
        buf[i] = saved;
    }

cleanup:
    free(buf);
    return rc;
}

/**
 * Ensure cfg->output_dir is a usable directory, creating it (and missing
 * parents) if needed. An existing non-directory is a clear error instead
 * of an opaque chart-writing failure later.
 */
static int prepare_output_dir(const char *dir)
{
    struct stat st;

    if (dir == NULL || dir[0] == '\0') {
        fprintf(stderr, "pcapstat: empty output directory\n");
        return PCAPSTAT_ERR_ARGS;
    }

    if (stat(dir, &st) != 0) {
        if (errno != ENOENT) {
            fprintf(stderr, "pcapstat: cannot access output directory '%s': %s\n",
                    dir, strerror(errno));
            return PCAPSTAT_ERR_IO;
        }
        int rc = make_dirs(dir);
        if (rc != PCAPSTAT_OK)
            return rc;
        if (stat(dir, &st) != 0) {
            fprintf(stderr, "pcapstat: cannot access output directory '%s': %s\n",
                    dir, strerror(errno));
            return PCAPSTAT_ERR_IO;
        }
    }

    if (!S_ISDIR(st.st_mode)) {
        fprintf(stderr,
                "pcapstat: output path '%s' exists and is not a directory\n",
                dir);
        return PCAPSTAT_ERR_IO;
    }
    return PCAPSTAT_OK;
}

int cli_validate_and_prepare(cli_config_t *cfg)
{
    if (cfg == NULL)
        return PCAPSTAT_ERR_ARGS;
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

    int rc = skip_duplicate_inputs(cfg);
    if (rc != PCAPSTAT_OK)
        return rc;

    return prepare_output_dir(cfg->output_dir);
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
