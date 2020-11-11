/* SPDX-License-Identifier: LGPL-2.1+ */

#include <fcntl.h>

#include "alloc-util.h"
#include "env-util.h"
#include "escape.h"
#include "fileio.h"
#include "missing_mman.h"
#include "missing_syscall.h"
#include "parse-util.h"
#include "process-util.h"
#include "serialize.h"
#include "strv.h"
#include "tmpfile-util.h"

int serialize_item(FILE *f, const char *key, const char *value) {
        assert(f);
        assert(key);

        if (!value)
                return 0;

        /* Make sure that anything we serialize we can also read back again with read_line() with a maximum line size
         * of LONG_LINE_MAX. This is a safety net only. All code calling us should filter this out earlier anyway. */
        if (strlen(key) + 1 + strlen(value) + 1 > LONG_LINE_MAX) {
                log_warning("Attempted to serialize overly long item '%s', refusing.", key);
                return -EINVAL;
        }

        fputs(key, f);
        fputc('=', f);
        fputs(value, f);
        fputc('\n', f);

        return 1;
}

int serialize_item_escaped(FILE *f, const char *key, const char *value) {
        _cleanup_free_ char *c = NULL;

        assert(f);
        assert(key);

        if (!value)
                return 0;

        c = cescape(value);
        if (!c)
                return log_oom();

        return serialize_item(f, key, c);
}

int serialize_item_format(FILE *f, const char *key, const char *format, ...) {
        char buf[LONG_LINE_MAX];
        va_list ap;
        int k;

        assert(f);
        assert(key);
        assert(format);

        va_start(ap, format);
        k = vsnprintf(buf, sizeof(buf), format, ap);
        va_end(ap);

        if (k < 0 || (size_t) k >= sizeof(buf) || strlen(key) + 1 + k + 1 > LONG_LINE_MAX) {
                log_warning("Attempted to serialize overly long item '%s', refusing.", key);
                return -EINVAL;
        }

        fputs(key, f);
        fputc('=', f);
        fputs(buf, f);
        fputc('\n', f);

        return 1;
}

int serialize_fd(FILE *f, FDSet *fds, const char *key, int fd) {
        int copy;

        assert(f);
        assert(key);

        if (fd < 0)
                return 0;

        copy = fdset_put_dup(fds, fd);
        if (copy < 0)
                return log_error_errno(copy, "Failed to add file descriptor to serialization set: %m");

        return serialize_item_format(f, key, "%i", copy);
}

int serialize_usec(FILE *f, const char *key, usec_t usec) {
        assert(f);
        assert(key);

        if (usec == USEC_INFINITY)
                return 0;

        return serialize_item_format(f, key, USEC_FMT, usec);
}

int serialize_dual_timestamp(FILE *f, const char *name, const dual_timestamp *t) {
        assert(f);
        assert(name);
        assert(t);

        if (!dual_timestamp_is_set(t))
                return 0;

        return serialize_item_format(f, name, USEC_FMT " " USEC_FMT, t->realtime, t->monotonic);
}

int serialize_limbo_bpf_program(FILE *f, FDSet *fds, BPFProgram *p) {
        int copy;

        /* We don't actually need the instructions or other data, since this is only used on the other side
         * for BPF limbo, which just requires the program type (inferred, not stored), cgroup path (stored),
         * and kernel-facing BPF file descriptor (stored). We don't even need to know what unit it's attached
         * to, since we're just going to expire it after coldplug. */

        assert(f);
        assert(key);
        assert(p);

        assert(p->n_ref == 1);
        assert(p->kernel_fd > 0);
        assert(p->attached_path);

        copy = fdset_put_dup(fds, p->kernel_fd);
        if (copy < 0)
                return log_error_errno(copy, "Failed to add file descriptor to serialization set: %m");

        return serialize_item_format(f, "bpf-limbo", "%i %i %i \"%s\"", copy, p->prog_type, p->attached_type, p->attached_path);
}

void deserialize_limbo_bpf_program(Manager *m, FDSet *fds, const char *value) {
        _cleanup_free_ char *raw_fd = NULL, *raw_pt = NULL, *raw_at = NULL, *raw_cgpath = NULL;
        BPFProgram *p;
        int fd, r, prog_type, attached_type;

        assert(m);
        assert(name);
        assert(value);

        r = extract_first_word(&value, &raw_fd, NULL, 0);
        if (r <= 0 || safe_atoi(raw_fd, &fd) < 0 || fd < 0 || !fdset_contains(fds, fd)) {
                log_unit_debug(u, "Failed to parse bpf-limbo FD: %s", value);
                return;
        }

        r = extract_first_word(&value, &raw_pt, NULL, 0);
        if (r <= 0 || safe_atoi(raw_pt, &prog_type) < 0) {
                log_unit_debug(u, "Failed to parse bpf-limbo program type: %s", value);
                return;
        }

        r = extract_first_word(&value, &raw_at, NULL, 0);
        if (r <= 0 || safe_atoi(raw_at, &attached_type) < 0) {
                log_unit_debug(u, "Failed to parse bpf-limbo attached type: %s", value);
                return;
        }

        r = extract_first_word(&value, &raw_cgpath, NULL, EXTRACT_CUNESCAPE | EXTRACT_UNQUOTE);
        if (r <= 0) {
                log_unit_debug_errno(u, r, "Failed to parse attached path for BPF limbo FD %s: %m", value);
                return;
        }

        r = bpf_program_new(prog_type, &p);
        if (r < 0) {
                log_unit_error_errno(u, r, "Failed to create BPF limbo program", name);
                return;
        }

        /* Just enough to free it when the time is right, this does not have enough information be used as a
         * real BPFProgram. */
        p->attached_type = attached_type;
        p->kernel_fd = fdset_remove(fds, fd);
        p->attached_path = strdup(raw_cgpath);

        r = set_ensure_put(&m->bpf_limbo_progs, NULL, p);
        if (r < 0) {
                log_unit_debug(u, "Failed to register BPF limbo program for FD %s", value);
                (void) bpf_program_unref(p);
        }
}


int serialize_strv(FILE *f, const char *key, char **l) {
        int ret = 0, r;
        char **i;

        /* Returns the first error, or positive if anything was serialized, 0 otherwise. */

        STRV_FOREACH(i, l) {
                r = serialize_item_escaped(f, key, *i);
                if ((ret >= 0 && r < 0) ||
                    (ret == 0 && r > 0))
                        ret = r;
        }

        return ret;
}

int deserialize_usec(const char *value, usec_t *ret) {
        int r;

        assert(value);

        r = safe_atou64(value, ret);
        if (r < 0)
                return log_debug_errno(r, "Failed to parse usec value \"%s\": %m", value);

        return 0;
}

int deserialize_dual_timestamp(const char *value, dual_timestamp *t) {
        uint64_t a, b;
        int r, pos;

        assert(value);
        assert(t);

        pos = strspn(value, WHITESPACE);
        if (value[pos] == '-')
                return -EINVAL;
        pos += strspn(value + pos, DIGITS);
        pos += strspn(value + pos, WHITESPACE);
        if (value[pos] == '-')
                return -EINVAL;

        r = sscanf(value, "%" PRIu64 "%" PRIu64 "%n", &a, &b, &pos);
        if (r != 2)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Failed to parse dual timestamp value \"%s\".",
                                       value);

        if (value[pos] != '\0')
                /* trailing garbage */
                return -EINVAL;

        t->realtime = a;
        t->monotonic = b;

        return 0;
}

int deserialize_environment(const char *value, char ***list) {
        _cleanup_free_ char *unescaped = NULL;
        int r;

        assert(value);
        assert(list);

        /* Changes the *environment strv inline. */

        r = cunescape(value, 0, &unescaped);
        if (r < 0)
                return log_error_errno(r, "Failed to unescape: %m");

        r = strv_env_replace(list, unescaped);
        if (r < 0)
                return log_error_errno(r, "Failed to append environment variable: %m");

        unescaped = NULL; /* now part of 'list' */
        return 0;
}

int open_serialization_fd(const char *ident) {
        int fd;

        fd = memfd_create(ident, MFD_CLOEXEC);
        if (fd < 0) {
                const char *path;

                path = getpid_cached() == 1 ? "/run/systemd" : "/tmp";
                fd = open_tmpfile_unlinkable(path, O_RDWR|O_CLOEXEC);
                if (fd < 0)
                        return fd;

                log_debug("Serializing %s to %s.", ident, path);
        } else
                log_debug("Serializing %s to memfd.", ident);

        return fd;
}
