/*
 * engkr_ctl.c - Userspace CLI & JSONL streamer for engkr_tracer
 * Build: aarch64-linux-gnu-gcc -static -O2 -Wall engkr_ctl.c -o engkr_ctl
 */

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

#include "engkr_tracer.h"

static volatile sig_atomic_t g_stop = 0;

static void handle_sig(int sig)
{
	(void)sig;
	g_stop = 1;
}

static long engkr_prctl(unsigned long cmd, unsigned long a3,
			unsigned long a4, unsigned long a5)
{
	return prctl(PR_ENGKR_TRACER, cmd, a3, a4, a5);
}

static const char *evt_type_name(uint16_t type)
{
	switch (type) {
	case EVT_MARKER:        return "MARKER";
	case EVT_AUTO_UID_LOCK: return "AUTO_UID_LOCK";
	case EVT_OPEN:          return "OPEN";
	case EVT_FACCESSAT:     return "FACCESSAT";
	case EVT_STAT:          return "STAT";
	case EVT_STATFS:        return "STATFS";
	case EVT_READLINK:      return "READLINK";
	case EVT_READDIR:       return "READDIR";
	case EVT_UNLINK:        return "UNLINK";
	case EVT_RENAME:        return "RENAME";
	case EVT_MKDIR:         return "MKDIR";
	case EVT_GETXATTR:      return "GETXATTR";
	case EVT_SETXATTR:      return "SETXATTR";
	case EVT_MMAP:          return "MMAP";
	case EVT_EXECVE:        return "EXECVE";
	case EVT_UNAME:         return "UNAME";
	case EVT_PTRACE:        return "PTRACE";
	default:                return "UNKNOWN";
	}
}

static void print_json_escaped(FILE *out, const char *s, size_t maxlen)
{
	size_t i;

	fputc('"', out);
	for (i = 0; i < maxlen && s[i] != '\0'; i++) {
		unsigned char c = (unsigned char)s[i];

		switch (c) {
		case '"':  fputs("\\\"", out); break;
		case '\\': fputs("\\\\", out); break;
		case '\b': fputs("\\b", out);  break;
		case '\f': fputs("\\f", out);  break;
		case '\n': fputs("\\n", out);  break;
		case '\r': fputs("\\r", out);  break;
		case '\t': fputs("\\t", out);  break;
		default:
			if (c < 0x20 || c >= 0x7f)
				fprintf(out, "\\u%04x", c);
			else
				fputc(c, out);
			break;
		}
	}
	fputc('"', out);
}

static void emit_event_jsonl(FILE *out, const struct engkr_event *ev)
{
	fprintf(out,
		"{\"ts_ns\":%llu,\"pid\":%u,\"tgid\":%u,\"uid\":%u,"
		"\"type\":\"%s\",\"flags\":%u,\"ret\":%d,\"aux\":%d,\"comm\":",
		(unsigned long long)ev->ts_ns,
		ev->pid, ev->tgid, ev->uid,
		evt_type_name(ev->type),
		(unsigned int)ev->flags,
		ev->ret, ev->aux);
	print_json_escaped(out, ev->comm, sizeof(ev->comm));
	fputs(",\"path\":", out);
	print_json_escaped(out, ev->path, sizeof(ev->path));
	fputs(",\"extra\":", out);
	print_json_escaped(out, ev->extra, sizeof(ev->extra));
	fputs("}\n", out);
}

static int print_stats(FILE *out)
{
	struct engkr_stats st;
	uint32_t i;

	memset(&st, 0, sizeof(st));
	if (engkr_prctl(ENGKR_CMD_GET_STATS, (unsigned long)&st, 0, 0) < 0) {
		perror("ENGKR_CMD_GET_STATS");
		return 1;
	}
	fprintf(out, "active:          %u\n", st.active);
	fprintf(out, "target_pkg:      %s\n", st.target_pkg[0] ? st.target_pkg : "(none)");
	fprintf(out, "uids (%u):        ", st.uid_count);
	for (i = 0; i < st.uid_count && i < ENGKR_MAX_UIDS; i++)
		fprintf(out, "%s%u", i ? ", " : "", st.uids[i]);
	if (st.uid_count == 0)
		fputs("(none)", out);
	fputc('\n', out);
	fprintf(out, "total_events:    %llu\n", (unsigned long long)st.total_events);
	fprintf(out, "dropped_events:  %llu\n", (unsigned long long)st.dropped_events);
	fprintf(out, "ring_used_bytes: %llu / %llu\n",
		(unsigned long long)st.ring_used_bytes,
		(unsigned long long)st.ring_size_bytes);
	return 0;
}

static int cmd_stream(const char *outfile)
{
	FILE *out = stdout;
	const size_t buf_evts = 256;
	const size_t buf_bytes = buf_evts * sizeof(struct engkr_event);
	struct engkr_event *buf;
	struct sigaction sa;

	if (outfile) {
		out = fopen(outfile, "a");
		if (!out) {
			perror("fopen");
			return 1;
		}
	}

	buf = (struct engkr_event *)malloc(buf_bytes);
	if (!buf) {
		fprintf(stderr, "malloc failed\n");
		if (outfile)
			fclose(out);
		return 1;
	}

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = handle_sig;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	while (!g_stop) {
		long n = engkr_prctl(ENGKR_CMD_READ_RING,
				     (unsigned long)buf, buf_bytes, 0);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			perror("ENGKR_CMD_READ_RING");
			break;
		}
		if (n > 0) {
			size_t count = (size_t)n / sizeof(struct engkr_event);
			size_t i;

			for (i = 0; i < count; i++)
				emit_event_jsonl(out, &buf[i]);
			fflush(out);
		} else {
			usleep(20000); /* 20ms poll interval */
		}
	}

	/* Final drain on exit */
	for (;;) {
		long n = engkr_prctl(ENGKR_CMD_READ_RING,
				     (unsigned long)buf, buf_bytes, 0);
		if (n <= 0)
			break;
		{
			size_t count = (size_t)n / sizeof(struct engkr_event);
			size_t i;

			for (i = 0; i < count; i++)
				emit_event_jsonl(out, &buf[i]);
		}
		fflush(out);
	}

	free(buf);
	if (outfile)
		fclose(out);

	fprintf(stderr, "\n--- engkr_ctl stream stopped ---\n");
	print_stats(stderr);
	return 0;
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s <command> [args]\n"
		"Commands:\n"
		"  status                 Show tracer status, UIDs, and counters\n"
		"  pkg <package_name>     Set target package for Auto-UID Lock & path trigger\n"
		"  add-uid <uid>          Add target UID (up to %d)\n"
		"  clear                  Clear target UIDs and package\n"
		"  start [--reset]        Enable tracing (lazy-allocates 8MB ring)\n"
		"  stop                   Disable tracing\n"
		"  reset                  Clear ring buffer and counters\n"
		"  marker <text>          Emit EVT_MARKER into ring buffer\n"
		"  stream [output.jsonl]  Stream events as JSONL (Ctrl-C to stop)\n",
		prog, ENGKR_MAX_UIDS);
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		usage(argv[0]);
		return 1;
	}

	if (strcmp(argv[1], "status") == 0) {
		return print_stats(stdout);
	} else if (strcmp(argv[1], "pkg") == 0 && argc >= 3) {
		if (engkr_prctl(ENGKR_CMD_SET_PKG, (unsigned long)argv[2], 0, 0) < 0) {
			perror("ENGKR_CMD_SET_PKG");
			return 1;
		}
		printf("[+] target_pkg set to: %s\n", argv[2]);
		return 0;
	} else if (strcmp(argv[1], "add-uid") == 0 && argc >= 3) {
		unsigned long uid = strtoul(argv[2], NULL, 10);
		if (engkr_prctl(ENGKR_CMD_ADD_UID, uid, 0, 0) < 0) {
			perror("ENGKR_CMD_ADD_UID");
			return 1;
		}
		printf("[+] added UID: %lu\n", uid);
		return 0;
	} else if (strcmp(argv[1], "clear") == 0) {
		if (engkr_prctl(ENGKR_CMD_CLEAR_UIDS, 0, 0, 0) < 0) {
			perror("ENGKR_CMD_CLEAR_UIDS");
			return 1;
		}
		printf("[+] cleared target UIDs and target_pkg\n");
		return 0;
	} else if (strcmp(argv[1], "start") == 0) {
		unsigned long do_reset = (argc >= 3 && strcmp(argv[2], "--reset") == 0) ? 1 : 0;
		if (engkr_prctl(ENGKR_CMD_ENABLE, do_reset, 0, 0) < 0) {
			perror("ENGKR_CMD_ENABLE");
			return 1;
		}
		printf("[+] engkr_tracer enabled\n");
		return 0;
	} else if (strcmp(argv[1], "stop") == 0) {
		if (engkr_prctl(ENGKR_CMD_DISABLE, 0, 0, 0) < 0) {
			perror("ENGKR_CMD_DISABLE");
			return 1;
		}
		printf("[+] engkr_tracer disabled\n");
		return 0;
	} else if (strcmp(argv[1], "reset") == 0) {
		if (engkr_prctl(ENGKR_CMD_RESET, 0, 0, 0) < 0) {
			perror("ENGKR_CMD_RESET");
			return 1;
		}
		printf("[+] engkr_tracer ring and counters reset\n");
		return 0;
	} else if (strcmp(argv[1], "marker") == 0 && argc >= 3) {
		if (engkr_prctl(ENGKR_CMD_MARKER, (unsigned long)argv[2], 0, 0) < 0) {
			perror("ENGKR_CMD_MARKER");
			return 1;
		}
		printf("[+] marker emitted: %s\n", argv[2]);
		return 0;
	} else if (strcmp(argv[1], "stream") == 0) {
		return cmd_stream(argc >= 3 ? argv[2] : NULL);
	}

	usage(argv[0]);
	return 1;
}
