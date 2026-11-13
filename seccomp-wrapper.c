/* SPDX-License-Identifier: MIT-0 */

/**
 * Requires libseccomp with support for seccomp user notifications, which at
 * the time of writing is only in the main branch.
 *
 * Execute a command with a configurable seccomp filter, socket and netlink
 * stubbing. Intended use is as a demo of seccomp capabilities, to lear how it
 * works, and also how netlink works, without requiring privileged access to
 * the kernel.
 *
 * Rule mode uses libseccomp to resolve syscalls, compile argument comparisons,
 * and load a filter before exec. Signed errno values from -4094 through zero
 * use SCMP_ACT_ERRNO; positive values and -4095 use user notifications so the
 * wrapper can supply the syscall result.
 *
 * Emulated actions fork an unfiltered supervisor and a filtered command child.
 * A temporary thread, started before the child loads its filter, transfers the
 * notification listener FD to the parent via SCM_RIGHTS. The parent services
 * notifications and propagates command status and signals.
 *
 * Socket actions create a fresh backing on each match and atomically inject
 * its FD with SECCOMP_ADDFD_FLAG_SEND. AF_UNIX backings are bound socketpairs:
 * the supervisor retains their peers to buffer outgoing data. Process-connector
 * requests can receive protocol ACKs on these peers.
 *
 * --stub-netlink-connector automatically intercepts netlin k connector socket
 * creation and related setup, send, and receive calls. It uses pidfd_getfd and
 * SO_COOKIE to recognize backing sockets across dup/fork and FD reuse, and
 * process_vm reads/writes to decode caller buffers and return sockaddr_nl and
 * control data. Port IDs, memberships, registrations, and kernel-source ACKs
 * are emulated in userspace, and no process events are generated.
 *
 * The full stub requires native direct syscalls and Linux 6.9+ thread pidfds.
 * Memory access and FD duplication require CAP_SYS_PTRACE permission checks.
 */

#define _GNU_SOURCE

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <linux/cn_proc.h>
#include <linux/connector.h>
#include <linux/filter.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/random.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <seccomp.h>

#define CONNECTOR_ACK_SIZE \
	(NLMSG_HDRLEN + sizeof(struct cn_msg) + sizeof(struct proc_event))
#define CONNECTOR_INPUT_SIZE (NLMSG_HDRLEN + CONNECTOR_MAX_MSG_SIZE)
#ifndef PIDFD_THREAD
#define PIDFD_THREAD O_EXCL
#endif

_Static_assert(CONNECTOR_ACK_SIZE == 76, "update the connector ACK wire format");
_Static_assert(offsetof(struct proc_event, event_data) == 16,
	       "update the process-event ACK layout");

struct action {
	uint32_t code;
	int64_t value;
	bool emulated;
	bool socket;
	int family;
	int kind;
	int protocol;
};

struct socket_peer {
	int fd;
	int kind;
	bool connector;
	uint32_t sequence;
	unsigned char *input;
	size_t input_len;
	unsigned char output[CONNECTOR_ACK_SIZE];
	size_t output_len;
	size_t output_offset;
	struct socket_peer *next;
};

struct socket_name {
	const char *name;
	int value;
};

#define SOCKET_NAME(name) { #name, name }

static const struct socket_name socket_families[] = {
	SOCKET_NAME(AF_UNSPEC), SOCKET_NAME(AF_UNIX), SOCKET_NAME(AF_LOCAL),
	SOCKET_NAME(AF_INET), SOCKET_NAME(AF_INET6), SOCKET_NAME(AF_NETLINK),
	SOCKET_NAME(AF_ROUTE), SOCKET_NAME(AF_PACKET), SOCKET_NAME(AF_VSOCK),
	SOCKET_NAME(AF_ALG), SOCKET_NAME(AF_APPLETALK), SOCKET_NAME(AF_ASH),
	SOCKET_NAME(AF_ATMPVC), SOCKET_NAME(AF_ATMSVC), SOCKET_NAME(AF_AX25),
	SOCKET_NAME(AF_BLUETOOTH), SOCKET_NAME(AF_BRIDGE), SOCKET_NAME(AF_CAN),
	SOCKET_NAME(AF_DECnet), SOCKET_NAME(AF_ECONET), SOCKET_NAME(AF_IPX),
	SOCKET_NAME(AF_IRDA), SOCKET_NAME(AF_KEY), SOCKET_NAME(AF_LLC),
	SOCKET_NAME(AF_NETBEUI), SOCKET_NAME(AF_NETROM), SOCKET_NAME(AF_PPPOX),
	SOCKET_NAME(AF_QIPCRTR), SOCKET_NAME(AF_RDS), SOCKET_NAME(AF_ROSE),
	SOCKET_NAME(AF_SECURITY), SOCKET_NAME(AF_SNA), SOCKET_NAME(AF_TIPC),
	SOCKET_NAME(AF_WANPIPE), SOCKET_NAME(AF_X25),
	{ NULL, 0 }
};

static const struct socket_name socket_kinds[] = {
	SOCKET_NAME(SOCK_STREAM), SOCKET_NAME(SOCK_DGRAM), SOCKET_NAME(SOCK_RAW),
	SOCKET_NAME(SOCK_RDM), SOCKET_NAME(SOCK_SEQPACKET),
	{ NULL, 0 }
};

static const struct socket_name socket_protocols[] = {
	{ "DEFAULT", 0 },
	{ "0", 0 },
	SOCKET_NAME(IPPROTO_IP), SOCKET_NAME(IPPROTO_TCP), SOCKET_NAME(IPPROTO_UDP),
	SOCKET_NAME(IPPROTO_ICMP), SOCKET_NAME(IPPROTO_ICMPV6),
	SOCKET_NAME(IPPROTO_RAW), SOCKET_NAME(IPPROTO_AH),
	SOCKET_NAME(IPPROTO_DSTOPTS), SOCKET_NAME(IPPROTO_EGP),
	SOCKET_NAME(IPPROTO_ESP), SOCKET_NAME(IPPROTO_FRAGMENT),
	SOCKET_NAME(IPPROTO_GRE), SOCKET_NAME(IPPROTO_HOPOPTS),
	SOCKET_NAME(IPPROTO_IDP), SOCKET_NAME(IPPROTO_IGMP),
	SOCKET_NAME(IPPROTO_IPIP), SOCKET_NAME(IPPROTO_IPV6),
	SOCKET_NAME(IPPROTO_NONE), SOCKET_NAME(IPPROTO_PIM),
	SOCKET_NAME(IPPROTO_PUP), SOCKET_NAME(IPPROTO_ROUTING),
	SOCKET_NAME(IPPROTO_RSVP), SOCKET_NAME(IPPROTO_SCTP),
	SOCKET_NAME(IPPROTO_TP), SOCKET_NAME(IPPROTO_UDPLITE),
#ifdef IPPROTO_MPTCP
	SOCKET_NAME(IPPROTO_MPTCP),
#endif
	SOCKET_NAME(NETLINK_ROUTE), SOCKET_NAME(NETLINK_UNUSED),
	SOCKET_NAME(NETLINK_USERSOCK), SOCKET_NAME(NETLINK_FIREWALL),
	SOCKET_NAME(NETLINK_SOCK_DIAG), SOCKET_NAME(NETLINK_INET_DIAG),
	SOCKET_NAME(NETLINK_NFLOG), SOCKET_NAME(NETLINK_XFRM),
	SOCKET_NAME(NETLINK_SELINUX), SOCKET_NAME(NETLINK_ISCSI),
	SOCKET_NAME(NETLINK_AUDIT), SOCKET_NAME(NETLINK_FIB_LOOKUP),
	SOCKET_NAME(NETLINK_CONNECTOR), SOCKET_NAME(NETLINK_NETFILTER),
	SOCKET_NAME(NETLINK_IP6_FW), SOCKET_NAME(NETLINK_DNRTMSG),
	SOCKET_NAME(NETLINK_KOBJECT_UEVENT), SOCKET_NAME(NETLINK_GENERIC),
	SOCKET_NAME(NETLINK_SCSITRANSPORT), SOCKET_NAME(NETLINK_ECRYPTFS),
	SOCKET_NAME(NETLINK_RDMA), SOCKET_NAME(NETLINK_CRYPTO),
#ifdef NETLINK_SMC
	SOCKET_NAME(NETLINK_SMC),
#endif
	{ NULL, 0 }
};

#undef SOCKET_NAME

struct rule {
	const char *text;
	struct action action;
	int syscall;
	unsigned int arg_count;
	struct scmp_arg_cmp args[6];
	struct sock_filter *program;
	size_t program_count;
};

struct configuration {
	struct action def;
	uint32_t *arches;
	size_t arch_count;
	struct rule *rules;
	size_t rule_count;
	bool stub_connector;
};

struct listener_sender {
	int channel;
	atomic_int fd;
	int error;
};

static const int forwarded[] = {
	SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGUSR1, SIGUSR2, SIGALRM, SIGWINCH
};

static volatile sig_atomic_t child_pid;
static volatile sig_atomic_t forward_error;

enum stub_operation {
	STUB_SOCKET, STUB_BIND, STUB_CONNECT, STUB_SHUTDOWN, STUB_GETNAME, STUB_GETPEER,
	STUB_SETOPT, STUB_GETOPT, STUB_SENDTO, STUB_SENDMSG, STUB_SENDMMSG,
	STUB_WRITE, STUB_WRITEV, STUB_RECVFROM, STUB_RECVMSG, STUB_RECVMMSG
};

static struct {
	const char *name;
	enum stub_operation operation;
	int number;
} stub_calls[] = {
	{ "socket", STUB_SOCKET, -1 }, { "bind", STUB_BIND, -1 },
	{ "connect", STUB_CONNECT, -1 }, { "shutdown", STUB_SHUTDOWN, -1 },
	{ "getsockname", STUB_GETNAME, -1 },
	{ "getpeername", STUB_GETPEER, -1 }, { "setsockopt", STUB_SETOPT, -1 },
	{ "getsockopt", STUB_GETOPT, -1 }, { "sendto", STUB_SENDTO, -1 },
	{ "sendmsg", STUB_SENDMSG, -1 }, { "sendmmsg", STUB_SENDMMSG, -1 },
	{ "write", STUB_WRITE, -1 }, { "writev", STUB_WRITEV, -1 },
	{ "recvfrom", STUB_RECVFROM, -1 }, { "recvmsg", STUB_RECVMSG, -1 },
	{ "recvmmsg", STUB_RECVMMSG, -1 }
};

struct stub_socket {
	uint64_t cookie;
	int peer;
	int type;
	uint32_t port;
	uint32_t groups;
	uint32_t destination;
	uint32_t destination_group;
	uint32_t event_mask;
	uint32_t options;
	bool bound;
	bool groups_allocated;
	bool registered;
	bool listening;
	struct stub_socket *next;
};

struct stub_pending {
	struct seccomp_notif request;
	enum stub_operation operation;
	struct stub_socket *socket;
	int fd;
	unsigned int completed;
	uint64_t deadline;
	uint64_t batch_deadline;
	bool batch_timeout;
	struct stub_pending *next;
};

struct connector_stub {
	int listener;
	const char *prog;
	int access_error;
	uint32_t sequence;
	uint32_t next_port;
	struct stub_socket *sockets;
	struct stub_pending *pending;
};

/* Encode a connector ACK shared by rule peers and the full stub. */
static int build_connector_ack(struct socket_peer *peer,
			       const struct cn_msg *request, int error);

/* Map a native syscall number to an automatically emulated stub operation. */
static int stub_operation(int number)
{
	size_t i;

	for (i = 0; i < sizeof(stub_calls) / sizeof(stub_calls[0]); i++) {
		if (stub_calls[i].number >= 0 && stub_calls[i].number == number)
			return stub_calls[i].operation;
	}
	return -1;
}

/* Check thread-pidfd support and install the stub's notification rules. */
static int configure_connector_stub(scmp_filter_ctx filter)
{
	struct scmp_arg_cmp args[] = {
		SCMP_A0(SCMP_CMP_MASKED_EQ, UINT32_MAX, AF_NETLINK),
		SCMP_A2(SCMP_CMP_MASKED_EQ, UINT32_MAX, NETLINK_CONNECTOR)
	};
	int rc, pidfd;
	size_t i;

	/* Thread pidfds preserve descriptor-table identity after unshare(). */
	pidfd = syscall(SYS_pidfd_open, getpid(), PIDFD_THREAD);
	if (pidfd < 0)
		return -errno;
	close(pidfd);
	for (i = 0; i < sizeof(stub_calls) / sizeof(stub_calls[0]); i++) {
		stub_calls[i].number =
			seccomp_syscall_resolve_name(stub_calls[i].name);
		if (stub_calls[i].number < 0)
			return -EOPNOTSUPP;
		rc = seccomp_rule_add_exact_array(
			filter, SCMP_ACT_NOTIFY, stub_calls[i].number,
			stub_calls[i].operation == STUB_SOCKET ? 2 : 0, args);
		if (rc)
			return rc;
	}
	return 0;
}

/* Print a short usage line or the complete CLI help. */
static void usage(FILE *stream, const char *prog, bool full)
{
	fprintf(stream,
		"usage: %s [-h] [-d ACTION] [-r RULE] [-a ARCH] "
		"-- command [args...]\n", prog);
	if (!full)
		return;
	fprintf(stream,
		"\nLoad a seccomp filter, then execute a command.\n\n"
		"Options:\n"
		"  -h, --help                   show this help message\n"
		"  -d, --default-action ACTION  unmatched syscall action "
		"(default: allow)\n"
		"  -r, --rule RULE              add a rule; may be repeated\n"
		"  -a, --arch ARCH              add an architecture by name; "
		"may be repeated\n"
		"      --stub-netlink-connector emulate process-connector setup\n\n"
		"Connector stub mode:\n"
		"  Intercepts only AF_NETLINK/NETLINK_CONNECTOR socket creation. "
		"NETLINK_ROUTE\n"
		"  and other sockets are ignored. Models bind/connect, port IDs, "
		"memberships,\n"
		"  socket options and LISTEN/IGNORE registrations; produces "
		"kernel-source ACKs\n"
		"  through recvfrom/recvmsg/recvmmsg, but never process events. "
		"Read/readv,\n"
		"  poll/epoll, dup/fork, close and descriptor flags work on real "
		"backing fds.\n"
		"  Unlike real Netlink, shutdown() on a stub socket returns 0 "
		"as a no-op,\n"
		"  preserving its transport and subscription for later "
		"reconfiguration.\n"
		"  Requires native direct socket syscalls, Linux 6.9+ "
		"(thread pidfds), and\n"
		"  CAP_SYS_PTRACE. \n\n"
		"Actions (case-insensitive):\n"
		"  allow, kill (kill_thread), kill_process, trap, log, notify,\n"
		"  errno:NUMBER, trace:NUMBER, socket:FAMILY:KIND:PROTOCOL\n"
		"  errno:NUMBER skips the syscall and returns the signed "
		"numeric value.\n"
		"  Negative numbers specify errors (errno:-1 for EPERM, "
		"errno:-13 for EACCES);\n"
		"  zero and positive numbers specify successful return values.\n"
		"  Accepted values range from -4095 through "
		"9223372036854775807.\n"
		"  Symbolic errno names are not accepted.\n\n"
		"Socket actions:\n"
		"  Use named constants, e.g. AF_NETLINK:SOCK_DGRAM:"
		"NETLINK_CONNECTOR or\n"
		"  AF_UNIX:SOCK_STREAM:DEFAULT. DEFAULT and 0 mean protocol zero.\n"
		"  FAMILY and KIND must be names; KIND must be unflagged.\n"
		"  Every match creates a new socket in the supervisor and "
		"atomically\n"
		"  installs its fd in the calling process, without executing "
		"the syscall.\n"
		"  Socket creation errors are logged and returned\n"
		"  to the caller. Socket actions require Linux 5.14 or newer "
		"(ADDFD_FLAG_SEND).\n\n"
		"  AF_UNIX sockets are connected socketpairs with unique abstract "
		"addresses.\n"
		"  Their address length matches sockaddr_nl (12 bytes).\n"
		"  The supervisor retains the peers until the command exits.\n"
		"  Except for process-connector ACK handling below, outgoing "
		"data stays\n"
		"  buffered on these peers and no replies are generated.\n"
		"  Buffer limits still apply: full queues block sends or return "
		"EAGAIN.\n"
		"  For sendto/sendmsg with an explicit AF_NETLINK destination, "
		"use SOCK_SEQPACKET,\n"
		"  which ignores that destination when connected. SOCK_DGRAM "
		"and SOCK_STREAM\n"
		"  still reject incompatible explicit destinations.\n\n"
		"  AF_UNIX backings for intercepted direct socket(AF_NETLINK, "
		"..., NETLINK_CONNECTOR)\n"
		"  calls answer process-connector requests. LISTEN/IGNORE get "
		"a successful\n"
		"  NLMSG_DONE / PROC_EVENT_NONE ACK; invalid operations get "
		"positive EINVAL.\n"
		"  Connector ack is request.ack + 1. Both sequence fields use a "
		"per-socket\n"
		"  counter; CPU is 0 and timestamps are monotonic nanoseconds. "
		"No process\n"
		"  events are generated. Other traffic stays buffered; "
		"unrecognized frames\n"
		"  are logged and disable ACK handling for that socket.\n\n"
		"Rules:\n"
		"  ACTION,SYSCALL[,INDEX:OP:VALUE[:VALUE2]...]\n"
		"  SYSCALL is a name or native-architecture syscall number.\n"
		"  INDEX is 0..5; OP is eq, ne, lt, le, gt, ge, or masked_eq.\n"
		"  For masked_eq, use INDEX:masked_eq:MASK:VALUE.\n"
		"  Comparisons within a rule are ANDed; repeat rules for "
		"alternatives.\n"
		"  Each argument index may occur only once per rule.\n"
		"  Numbers accept decimal, 0x, 0o, and 0b notation. Negative\n"
		"  comparison values become unsigned 64-bit two's complement "
		"values.\n\n"
		"Examples:\n"
		"  %s --rule errno:-1,ptrace -- program arg\n"
		"  %s --rule errno:-13,write,0:eq:1 -- program arg\n"
		"  %s --rule errno:42,socket,0:eq:16 -- program arg\n"
		"  %s --rule errno:-13,openat,2:masked_eq:0x3:0x1 -- program\n"
		"  %s --rule socket:AF_UNIX:SOCK_SEQPACKET:0,socket,0:eq:16 "
		"-- program\n"
		"  %s --stub-netlink-connector -- program args\n\n"
		"The filter takes effect before exec, including for the wrapper "
		"itself.\n"
		"No implicit allow rules are added: restrictive defaults must "
		"permit execve\n"
		"and syscalls needed by the wrapper, loader, and command. Only "
		"the native\n"
		"architecture is included unless --arch is used.\n\n"
		"Positive returns, -4095, and socket actions require seccomp "
		"user notifications.\n"
		"An unfiltered supervisor stays alive until the command exits; "
		"other returns\n"
		"use direct exec.\n"
		"If multiple emulated return rules match, the first one wins. "
		"An emulated\n"
		"default applies when none match. Plain notify cannot be "
		"combined with\n"
		"emulated returns. errno actions never create real fds; socket "
		"actions do.\n",
		prog, prog, prog, prog, prog, prog);
}

/* Trim leading and trailing whitespace from a mutable string. */
static char *trim(char *text)
{
	char *end;

	while (isspace((unsigned char)*text))
		text++;
	end = text + strlen(text);
	while (end > text && isspace((unsigned char)end[-1]))
		*--end = '\0';
	return text;
}

/* Parse a bounded signed integer into its unsigned two's-complement form. */
static int parse_number(const char *text, uint64_t negative_max,
			uint64_t positive_max, uint64_t *result)
{
	uint64_t value = 0, limit;
	unsigned int base = 10, digit;
	bool negative = false, prefixed = false, leading_zero;
	bool previous_digit, have_digit = false;

	while (isspace((unsigned char)*text))
		text++;
	if (*text == '+' || *text == '-')
		negative = *text++ == '-';
	limit = negative ? negative_max : positive_max;
	leading_zero = *text == '0';
	if (leading_zero) {
		switch (tolower((unsigned char)text[1])) {
		case 'x':
			base = 16;
			break;
		case 'o':
			base = 8;
			break;
		case 'b':
			base = 2;
			break;
		}
		if (base != 10) {
			prefixed = true;
			text += 2;
		}
	}
	/* Match int(text, 0), including underscores and no implicit octal. */
	previous_digit = prefixed;
	while (*text && !isspace((unsigned char)*text)) {
		if (*text == '_') {
			if (!previous_digit)
				return -EINVAL;
			previous_digit = false;
			text++;
			continue;
		}
		if (*text >= '0' && *text <= '9')
			digit = *text - '0';
		else if (*text >= 'a' && *text <= 'f')
			digit = *text - 'a' + 10;
		else if (*text >= 'A' && *text <= 'F')
			digit = *text - 'A' + 10;
		else
			return -EINVAL;
		if (digit >= base)
			return -EINVAL;
		if (digit > limit || value > (limit - digit) / base)
			return -ERANGE;
		value = value * base + digit;
		have_digit = previous_digit = true;
		text++;
	}
	while (isspace((unsigned char)*text))
		text++;
	if (*text || !have_digit || !previous_digit ||
	    (!prefixed && leading_zero && value != 0))
		return -EINVAL;
	*result = negative ? -value : value;
	return 0;
}

/* Parse named family, kind, and protocol values for an emulated socket action. */
static int parse_socket_action(char *text, struct action *action)
{
	const struct socket_name *tables[] = {
		socket_families, socket_kinds, socket_protocols
	};
	const struct socket_name *entry;
	int values[3];
	char *field;
	size_t i;

	for (i = 0; i < 3; i++) {
		field = strsep(&text, ":");
		if (!field)
			return -EINVAL;
		field = trim(field);
		for (entry = tables[i]; entry->name; entry++) {
			if (!strcasecmp(field, entry->name))
				break;
		}
		if (!entry->name)
			return -EINVAL;
		values[i] = entry->value;
	}
	if (text)
		return -EINVAL;
	action->code = SCMP_ACT_NOTIFY;
	action->value = -1;
	action->emulated = true;
	action->socket = true;
	action->family = values[0];
	action->kind = values[1];
	action->protocol = values[2];
	return 0;
}

/* Parse a kernel action, signed synthetic return, or named socket action. */
static int parse_action(const char *text, struct action *action)
{
	static const struct {
		const char *name;
		uint32_t code;
	} actions[] = {
		{ "allow", SCMP_ACT_ALLOW },
		{ "kill", SCMP_ACT_KILL },
		{ "kill_thread", SCMP_ACT_KILL },
		{ "kill_process", SCMP_ACT_KILL_PROCESS },
		{ "trap", SCMP_ACT_TRAP },
		{ "log", SCMP_ACT_LOG },
		{ "notify", SCMP_ACT_NOTIFY }
	};
	char *copy, *name, *data;
	uint64_t number;
	size_t i;
	int rc = -EINVAL;

	copy = strdup(text);
	if (!copy)
		return -ENOMEM;
	memset(action, 0, sizeof(*action));
	data = trim(copy);
	name = strsep(&data, ":");
	if (!data) {
		for (i = 0; i < sizeof(actions) / sizeof(actions[0]); i++) {
			if (!strcasecmp(name, actions[i].name)) {
				action->code = actions[i].code;
				rc = 0;
				break;
			}
		}
	} else if (!strcasecmp(name, "errno")) {
		rc = parse_number(data, 4095, INT64_MAX, &number);
		if (rc)
			goto out;
		action->value = number <= INT64_MAX ?
				(int64_t)number : -(int64_t)~number - 1;
		action->emulated = action->value > 0 ||
				   action->value == -4095;
		action->code = action->emulated ? SCMP_ACT_NOTIFY :
			       SCMP_ACT_ERRNO(-action->value);
	} else if (!strcasecmp(name, "trace")) {
		rc = parse_number(data, 0, 0xffff, &number);
		if (!rc)
			action->code = SCMP_ACT_TRACE(number);
	} else if (!strcasecmp(name, "socket"))
		rc = parse_socket_action(data, action);
out:
	free(copy);
	return rc;
}

/* Parse one indexed syscall argument comparison, including optional masks. */
static int parse_comparison(char *text, struct scmp_arg_cmp *arg)
{
	static const struct {
		const char *name;
		enum scmp_compare op;
	} operators[] = {
		{ "eq", SCMP_CMP_EQ }, { "ne", SCMP_CMP_NE },
		{ "lt", SCMP_CMP_LT }, { "le", SCMP_CMP_LE },
		{ "gt", SCMP_CMP_GT }, { "ge", SCMP_CMP_GE },
		{ "masked_eq", SCMP_CMP_MASKED_EQ }
	};
	char *fields[4], *field;
	size_t count = 0, i;
	uint64_t index;
	int rc;

	while ((field = strsep(&text, ":"))) {
		if (count == 4)
			return -EINVAL;
		fields[count++] = trim(field);
	}
	if (count < 3)
		return -EINVAL;
	rc = parse_number(fields[0], 0, 5, &index);
	if (rc)
		return rc;
	arg->arg = index;
	for (i = 0; i < sizeof(operators) / sizeof(operators[0]); i++) {
		if (!strcasecmp(fields[1], operators[i].name)) {
			arg->op = operators[i].op;
			break;
		}
	}
	if (i == sizeof(operators) / sizeof(operators[0]) ||
	    count != (arg->op == SCMP_CMP_MASKED_EQ ? 4 : 3))
		return -EINVAL;
	rc = parse_number(fields[2], UINT64_C(1) << 63, UINT64_MAX,
			  &arg->datum_a);
	if (!rc && count == 4)
		rc = parse_number(fields[3], UINT64_C(1) << 63, UINT64_MAX,
				  &arg->datum_b);
	return rc;
}

/* Parse a rule's action, syscall, and nonduplicated argument comparisons. */
static int parse_rule(struct rule *rule)
{
	char *copy, *cursor, *field;
	uint64_t number;
	unsigned int used = 0;
	int rc = -EINVAL;

	copy = strdup(rule->text);
	if (!copy)
		return -ENOMEM;
	cursor = copy;
	field = strsep(&cursor, ",");
	rc = parse_action(trim(field), &rule->action);
	if (rc)
		goto out;
	field = strsep(&cursor, ",");
	if (!field || !*trim(field)) {
		rc = -EINVAL;
		goto out;
	}
	field = trim(field);
	rc = parse_number(field, UINT64_C(1) << 31, INT32_MAX, &number);
	if (!rc)
		rule->syscall = number <= INT32_MAX ?
				(int)number : -(int)~number - 1;
	else
		rule->syscall = seccomp_syscall_resolve_name(field);
	if (rule->syscall == __NR_SCMP_ERROR) {
		rc = -EINVAL;
		goto out;
	}
	while ((field = strsep(&cursor, ","))) {
		struct scmp_arg_cmp *arg;

		if (rule->arg_count == 6) {
			rc = -EINVAL;
			goto out;
		}
		arg = &rule->args[rule->arg_count++];
		rc = parse_comparison(field, arg);
		if (rc)
			goto out;
		if (used & (1U << arg->arg)) {
			rc = -EINVAL;
			goto out;
		}
		used |= 1U << arg->arg;
	}
	rc = 0;
out:
	free(copy);
	return rc;
}

/* Initialize a libseccomp filter with the default action and requested ABIs. */
static int create_filter(uint32_t action, const struct configuration *config,
			 scmp_filter_ctx *filter)
{
	size_t i;
	int rc;

	*filter = seccomp_init(action);
	if (!*filter)
		return -EINVAL;
	for (i = 0; i < config->arch_count; i++) {
		rc = seccomp_arch_exist(*filter, config->arches[i]);
		if (rc == -EEXIST)
			rc = seccomp_arch_add(*filter, config->arches[i]);
		if (rc) {
			seccomp_release(*filter);
			*filter = NULL;
			return rc;
		}
	}
	return 0;
}

/* Add a kernel rule and compile a BPF matcher for any emulated action. */
static int add_rule(scmp_filter_ctx filter, struct rule *rule,
		    const struct configuration *config)
{
	scmp_filter_ctx matcher = NULL;
	size_t size = 0;
	int rc;

	if (!rule->action.emulated || config->def.code != SCMP_ACT_NOTIFY) {
		rc = seccomp_rule_add_array(filter, rule->action.code,
					   rule->syscall, rule->arg_count,
					   rule->args);
		if (rc)
			return rc;
	}
	if (!rule->action.emulated)
		return 0;
	/* Use libseccomp for identical ABI rewrites and argument widths. */
	rc = create_filter(SCMP_ACT_ALLOW, config, &matcher);
	if (rc)
		return rc;
	rc = seccomp_rule_add_array(matcher, SCMP_ACT_NOTIFY, rule->syscall,
				   rule->arg_count, rule->args);
	if (rc)
		goto out;
	rc = seccomp_export_bpf_mem(matcher, NULL, &size);
	if (rc)
		goto out;
	if (!size || size % sizeof(*rule->program)) {
		rc = -EINVAL;
		goto out;
	}
	rule->program = malloc(size);
	if (!rule->program) {
		rc = -ENOMEM;
		goto out;
	}
	rc = seccomp_export_bpf_mem(matcher, rule->program, &size);
	if (!rc)
		rule->program_count = size / sizeof(*rule->program);
out:
	seccomp_release(matcher);
	return rc;
}

/* Evaluate a libseccomp-generated matcher against a captured syscall record. */
static int evaluate_bpf(const struct rule *rule,
			const struct seccomp_data *data, uint32_t *action)
{
	uint32_t accumulator = 0;
	size_t pc = 0, jump;

	while (pc < rule->program_count) {
		const struct sock_filter *ins = &rule->program[pc++];

		jump = 0;
		switch (ins->code) {
		case BPF_LD + BPF_W + BPF_ABS:
			if (ins->k > sizeof(*data) - sizeof(accumulator))
				return -EINVAL;
			memcpy(&accumulator, (const char *)data + ins->k,
			       sizeof(accumulator));
			break;
		case BPF_ALU + BPF_OR + BPF_K:
			accumulator |= ins->k;
			break;
		case BPF_ALU + BPF_AND + BPF_K:
			accumulator &= ins->k;
			break;
		case BPF_JMP + BPF_JA:
			jump = ins->k;
			break;
		case BPF_JMP + BPF_JEQ + BPF_K:
			jump = accumulator == ins->k ? ins->jt : ins->jf;
			break;
		case BPF_JMP + BPF_JGT + BPF_K:
			jump = accumulator > ins->k ? ins->jt : ins->jf;
			break;
		case BPF_JMP + BPF_JGE + BPF_K:
			jump = accumulator >= ins->k ? ins->jt : ins->jf;
			break;
		case BPF_RET + BPF_K:
			*action = ins->k;
			return 0;
		default:
			return -EOPNOTSUPP;
		}
		if (jump > rule->program_count - pc)
			return -EINVAL;
		pc += jump;
	}
	return -EINVAL;
}

/* Identify direct socket(AF_NETLINK, ..., NETLINK_CONNECTOR) requests. */
static bool is_proc_connector(const struct seccomp_data *data)
{
	uint32_t arch = data->arch;
	char *name;
	bool result;

	if ((uint32_t)data->args[0] != AF_NETLINK ||
	    (uint32_t)data->args[2] != NETLINK_CONNECTOR)
		return false;
	if (arch == SCMP_ARCH_X86_64 && (data->nr & 0x40000000))
		arch = SCMP_ARCH_X32;
	name = seccomp_syscall_resolve_num_arch(arch, data->nr);
	if (!name)
		return false;
	result = !strcmp(name, "socket");
	free(name);
	return result;
}

/* Bind a unique abstract UNIX address with sockaddr_nl's address length. */
static int bind_backing_socket(int fd)
{
	struct sockaddr_un address = { .sun_family = AF_UNIX };
	const size_t name_size = sizeof(struct sockaddr_nl) -
				offsetof(struct sockaddr_un, sun_path) - 1;
	size_t filled;
	ssize_t received;
	unsigned int attempt;

	for (attempt = 0; attempt < 16; attempt++) {
		filled = 0;
		while (filled < name_size) {
			received = getrandom(address.sun_path + 1 + filled,
					     name_size - filled, 0);
			if (received < 0) {
				if (errno == EINTR)
					continue;
				return -errno;
			}
			if (!received)
				return -EIO;
			filled += received;
		}
		if (bind(fd, (struct sockaddr *)&address,
			 sizeof(struct sockaddr_nl)) == 0)
			return 0;
		if (errno != EADDRINUSE)
			return -errno;
	}
	return -EADDRINUSE;
}

/* Create a socket or bound UNIX pair, returning any peer to retain. */
static int create_backing_socket(const struct action *action,
				 struct socket_peer **peer)
{
	int fds[2], fd, rc;

	*peer = NULL;
	if (action->family != AF_UNIX) {
		fd = socket(action->family, action->kind | SOCK_CLOEXEC,
			    action->protocol);
		return fd < 0 ? -errno : fd;
	}
	if (socketpair(AF_UNIX, action->kind | SOCK_CLOEXEC,
		       action->protocol, fds) < 0)
		return -errno;
	rc = bind_backing_socket(fds[0]);
	if (!rc)
		rc = bind_backing_socket(fds[1]);
	if (rc)
		goto fail;
	if (fds[1] < 3) {
		fd = fcntl(fds[1], F_DUPFD_CLOEXEC, 3);
		if (fd < 0) {
			rc = -errno;
			goto fail;
		}
		close(fds[1]);
		fds[1] = fd;
	}
	*peer = calloc(1, sizeof(**peer));
	if (!*peer) {
		rc = -ENOMEM;
		goto fail;
	}
	(*peer)->fd = fds[1];
	(*peer)->kind = action->kind;
	return fds[0];
fail:
	close(fds[0]);
	close(fds[1]);
	return rc;
}

/* Close retained peers and free their connector input buffers and state. */
static void release_socket_peers(struct socket_peer *peer)
{
	struct socket_peer *next;

	while (peer) {
		next = peer->next;
		close(peer->fd);
		free(peer->input);
		free(peer);
		peer = next;
	}
}

/* Check that the target still has the given seccomp notification pending. */
static int stub_valid(struct connector_stub *stub,
		      const struct seccomp_notif *request)
{
	int rc;

	do {
		rc = ioctl(stub->listener, SECCOMP_IOCTL_NOTIF_ID_VALID,
			   &request->id);
	} while (rc < 0 && errno == EINTR);
	return rc < 0 ? -errno : 0;
}

/* Record and report a fatal failure to access the target process. */
static void stub_access_error(struct connector_stub *stub, pid_t pid, int error)
{
	stub->access_error = error;
	fprintf(stderr, "%s: connector stub cannot inspect process %d: %s. "
		"The supervisor needs ptrace access (CAP_SYS_PTRACE after UID "
		"changes or when the target is nondumpable).\n",
		stub->prog, pid, strerror(error));
}

/* Copy target memory while checking that the notification remains valid. */
static int stub_memory(struct connector_stub *stub,
		       const struct seccomp_notif *request, uint64_t address,
		       void *buffer, size_t size, bool write)
{
	struct iovec local, remote;
	ssize_t copied;
	size_t offset = 0;
	int rc;

	if (size && (!address || address > UINTPTR_MAX - size))
		return -EFAULT;
	while (offset < size) {
		rc = stub_valid(stub, request);
		if (rc)
			return rc;
		local.iov_base = (char *)buffer + offset;
		local.iov_len = size - offset;
		remote.iov_base = (void *)(uintptr_t)(address + offset);
		remote.iov_len = local.iov_len;
		if (write)
			copied = process_vm_writev(request->pid, &local, 1,
						   &remote, 1, 0);
		else
			copied = process_vm_readv(request->pid, &local, 1,
						  &remote, 1, 0);
		if (copied < 0) {
			rc = errno;
			if (rc == EINTR)
				continue;
			if (rc == EPERM || rc == EACCES || rc == ENOSYS)
				stub_access_error(stub, request->pid, rc);
			return -rc;
		}
		if (!copied)
			return -EFAULT;
		offset += copied;
	}
	return 0;
}

/* Reply with a syscall result or request native syscall continuation. */
static int stub_reply(struct connector_stub *stub,
		      const struct seccomp_notif *request, int64_t value,
		      bool continue_syscall)
{
	struct seccomp_notif_resp response = {
		.id = request->id,
		.val = value >= 0 ? value : 0,
		.error = value < 0 ? value : 0,
		.flags = continue_syscall ? SECCOMP_USER_NOTIF_FLAG_CONTINUE : 0
	};
	int rc;

	do {
		rc = ioctl(stub->listener, SECCOMP_IOCTL_NOTIF_SEND, &response);
	} while (rc < 0 && errno == EINTR);
	return rc < 0 && errno != ENOENT ? -errno : 0;
}

/* Get monotonic nanoseconds, returning zero if the clock query fails. */
static uint64_t stub_now(void)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
		return 0;
	return (uint64_t)now.tv_sec * 1000000000U + now.tv_nsec;
}

/* Release stub sockets whose caller endpoints have all been closed. */
static int stub_prune(struct connector_stub *stub)
{
	struct stub_socket **link = &stub->sockets, *item;
	struct pollfd fd;
	int rc;

	while (*link) {
		item = *link;
		fd = (struct pollfd) { .fd = item->peer };
		do {
			rc = poll(&fd, 1, 0);
		} while (rc < 0 && errno == EINTR);
		if (rc < 0)
			return -errno;
		if (fd.revents & POLLNVAL)
			return -EBADF;
		if (fd.revents & (POLLHUP | POLLERR)) {
			*link = item->next;
			close(item->peer);
			free(item);
		} else
			link = &item->next;
	}
	return 0;
}

/* Release pending receive descriptors and all full-stub socket state. */
static void stub_release(struct connector_stub *stub)
{
	struct stub_pending *pending;
	struct stub_socket *item;

	while ((pending = stub->pending)) {
		stub->pending = pending->next;
		close(pending->fd);
		free(pending);
	}
	while ((item = stub->sockets)) {
		stub->sockets = item->next;
		close(item->peer);
		free(item);
	}
}

/* Duplicate a target FD and identify a stub socket by its stable cookie. */
static int stub_lookup(struct connector_stub *stub,
		       const struct seccomp_notif *request,
		       struct stub_socket **found)
{
	struct stub_socket *item;
	struct stat st;
	uint64_t cookie;
	socklen_t size = sizeof(cookie);
	int pidfd, fd, error;

	*found = NULL;
	pidfd = syscall(SYS_pidfd_open, request->pid, PIDFD_THREAD);
	if (pidfd < 0)
		return -errno;
	fd = syscall(SYS_pidfd_getfd, pidfd, (int)request->data.args[0], 0);
	error = errno;
	close(pidfd);
	if (fd < 0) {
		if (error == EPERM || error == EACCES || error == ENOSYS)
			stub_access_error(stub, request->pid, error);
		return -error;
	}
	if (fstat(fd, &st) < 0) {
		error = errno;
		close(fd);
		return -error;
	}
	if (!S_ISSOCK(st.st_mode))
		return fd;
	if (getsockopt(fd, SOL_SOCKET, SO_COOKIE, &cookie, &size) < 0) {
		error = errno;
		close(fd);
		return -error;
	}
	for (item = stub->sockets; item; item = item->next) {
		if (item->cookie == cookie) {
			*found = item;
			break;
		}
	}
	return fd;
}

/* Create and inject a fresh connector backing while preserving socket flags. */
static int stub_create(struct connector_stub *stub,
		       const struct seccomp_notif *request)
{
	struct stub_socket *item;
	struct seccomp_notif_addfd addfd = { .id = request->id,
					   .flags = SECCOMP_ADDFD_FLAG_SEND };
	int type = request->data.args[1];
	int base = type & ~(SOCK_CLOEXEC | SOCK_NONBLOCK);
	int fds[2], rc, error;
	socklen_t size;

	if (type & ~(SOCK_CLOEXEC | SOCK_NONBLOCK | 0xf))
		return stub_reply(stub, request, -EINVAL, false);
	if (base != SOCK_DGRAM && base != SOCK_RAW)
		return stub_reply(stub, request, -ESOCKTNOSUPPORT, false);
	item = calloc(1, sizeof(*item));
	if (!item)
		return stub_reply(stub, request, -ENOMEM, false);
	if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC |
		       (type & SOCK_NONBLOCK), 0, fds) < 0) {
		error = errno;
		free(item);
		return stub_reply(stub, request, -error, false);
	}
	size = sizeof(item->cookie);
	if (getsockopt(fds[0], SOL_SOCKET, SO_COOKIE, &item->cookie, &size) < 0) {
		error = errno;
		close(fds[0]);
		close(fds[1]);
		free(item);
		return -error;
	}
	item->type = base;
	item->peer = fds[1];
	addfd.srcfd = fds[0];
	addfd.newfd_flags = type & SOCK_CLOEXEC ? O_CLOEXEC : 0;
	do {
		rc = ioctl(stub->listener, SECCOMP_IOCTL_NOTIF_ADDFD, &addfd);
	} while (rc < 0 && errno == EINTR);
	error = errno;
	close(fds[0]);
	if (rc < 0) {
		close(fds[1]);
		free(item);
		if (error == ENOENT)
			return 0;
		if (error == EMFILE || error == ENFILE)
			return stub_reply(stub, request, -error, false);
		return -error;
	}
	item->next = stub->sockets;
	stub->sockets = item;
	return 0;
}

/* Read a thread's thread-group ID from its procfs status. */
static int stub_tgid(pid_t tid)
{
	char path[64], line[256];
	FILE *file;
	int tgid = -ESRCH;

	snprintf(path, sizeof(path), "/proc/%d/status", tid);
	file = fopen(path, "re");
	if (!file)
		return -errno;
	while (fgets(line, sizeof(line), file)) {
		if (sscanf(line, "Tgid: %d", &tgid) == 1)
			break;
	}
	if (ferror(file))
		tgid = -EIO;
	fclose(file);
	return tgid;
}

/* Check whether a bound stub socket already owns a local Netlink port ID. */
static bool stub_port_used(struct connector_stub *stub, uint32_t port)
{
	struct stub_socket *item;

	for (item = stub->sockets; item; item = item->next) {
		if (item->bound && item->port == port)
			return true;
	}
	return false;
}

/* Allocate a unique local Netlink port ID for an unbound stub socket. */
static int stub_autobind(struct connector_stub *stub,
			 const struct seccomp_notif *request,
			 struct stub_socket *item)
{
	int tgid, rc;
	uint32_t port;

	if (item->bound)
		return 0;
	rc = stub_prune(stub);
	if (rc)
		return rc;
	tgid = stub_tgid(request->pid);
	if (tgid < 0)
		return tgid;
	port = tgid;
	while (!port || stub_port_used(stub, port))
		port = --stub->next_port;
	item->port = port;
	item->bound = true;
	return 0;
}

/* Read and validate a target sockaddr_nl or an AF_UNSPEC disconnect. */
static int stub_read_address(struct connector_stub *stub,
			     const struct seccomp_notif *request,
			     uint64_t pointer, uint32_t size,
			     struct sockaddr_nl *address, bool disconnect)
{
	unsigned char buffer[sizeof(struct sockaddr_storage)];
	int rc;

	if (size < sizeof(sa_family_t) || size > sizeof(buffer))
		return -EINVAL;
	rc = stub_memory(stub, request, pointer, buffer, size, false);
	if (rc)
		return rc;
	memset(address, 0, sizeof(*address));
	memcpy(address, buffer, size < sizeof(*address) ? size : sizeof(*address));
	if (disconnect && address->nl_family == AF_UNSPEC)
		return 0;
	if (size < sizeof(*address) || address->nl_family != AF_NETLINK)
		return -EINVAL;
	return 0;
}

/* Copy a Netlink address to the target and report its full address length. */
static int stub_write_address(struct connector_stub *stub,
			      const struct seccomp_notif *request,
			      uint64_t pointer, uint64_t length,
			      const struct sockaddr_nl *address)
{
	int supplied, actual = sizeof(*address), rc;

	rc = stub_memory(stub, request, length, &supplied, sizeof(supplied), false);
	if (rc)
		return rc;
	if (supplied < 0)
		return -EINVAL;
	rc = stub_memory(stub, request, pointer, (void *)address,
			 supplied < actual ? supplied : actual, true);
	if (!rc)
		rc = stub_memory(stub, request, length, &actual, sizeof(actual), true);
	return rc;
}

/* Apply bind, connect, or disconnect semantics to a stub socket. */
static int stub_bind_connect(struct connector_stub *stub,
			     const struct seccomp_notif *request,
			     struct stub_socket *item, bool connect)
{
	struct sockaddr_nl address;
	int rc;

	rc = stub_read_address(stub, request, request->data.args[1],
			       request->data.args[2], &address, connect);
	if (rc)
		return rc;
	if (connect) {
		if (address.nl_family == AF_UNSPEC) {
			item->destination = item->destination_group = 0;
			return 0;
		}
		rc = stub_autobind(stub, request, item);
		if (rc)
			return rc;
		item->destination = address.nl_pid;
		item->destination_group = address.nl_groups & -address.nl_groups;
		return 0;
	}
	if (item->bound && item->port != address.nl_pid)
		return -EINVAL;
	if (!item->bound) {
		rc = stub_prune(stub);
		if (rc)
			return rc;
		if (address.nl_pid) {
			if (stub_port_used(stub, address.nl_pid))
				return -EADDRINUSE;
			item->bound = true;
			item->port = address.nl_pid;
		} else {
			rc = stub_autobind(stub, request, item);
			if (rc)
				return rc;
		}
	}
	item->groups = address.nl_groups;
	item->groups_allocated |= address.nl_groups != 0;
	return 0;
}

/* Recognize supported boolean SOL_NETLINK socket options. */
static bool stub_netlink_option(int option)
{
	switch (option) {
	case NETLINK_PKTINFO:
	case NETLINK_BROADCAST_ERROR:
	case NETLINK_NO_ENOBUFS:
	case NETLINK_LISTEN_ALL_NSID:
	case NETLINK_CAP_ACK:
	case NETLINK_EXT_ACK:
	case NETLINK_GET_STRICT_CHK:
		return true;
	default:
		return false;
	}
}

/* Return emulated Netlink options or query the backing's SOL_SOCKET options. */
static int stub_getopt(struct connector_stub *stub,
		       const struct seccomp_notif *request,
		       struct stub_socket *item, int fd)
{
	int level = request->data.args[1], option = request->data.args[2];
	int length, value, rc;
	unsigned char buffer[256];
	socklen_t size;

	rc = stub_memory(stub, request, request->data.args[4], &length,
			 sizeof(length), false);
	if (rc)
		return rc;
	if (length < 0)
		return -EINVAL;
	size = (size_t)length < sizeof(buffer) ? (size_t)length : sizeof(buffer);
	if (level == SOL_NETLINK) {
		if (option == NETLINK_LIST_MEMBERSHIPS) {
			value = item->groups;
			size = item->groups_allocated ? sizeof(value) : 0;
			if (size && length >= (int)sizeof(value)) {
				rc = stub_memory(stub, request, request->data.args[3],
						 &value, sizeof(value), true);
				if (rc)
					return rc;
			}
			return stub_memory(stub, request, request->data.args[4],
					   &size, sizeof(size), true);
		}
		if (!stub_netlink_option(option))
			return -ENOPROTOOPT;
		if (length < (int)sizeof(value))
			return -EINVAL;
		value = !!(item->options & (1U << option));
		size = sizeof(value);
		memcpy(buffer, &value, size);
	} else if (level == SOL_SOCKET &&
		   (option == SO_DOMAIN || option == SO_TYPE ||
		    option == SO_PROTOCOL)) {
		value = option == SO_DOMAIN ? AF_NETLINK :
			option == SO_TYPE ? item->type : NETLINK_CONNECTOR;
		if (size > sizeof(value))
			size = sizeof(value);
		memcpy(buffer, &value, size);
	} else if (level == SOL_SOCKET) {
		if (getsockopt(fd, level, option, buffer, &size) < 0)
			return -errno;
	} else
		return -ENOPROTOOPT;
	rc = stub_memory(stub, request, request->data.args[3], buffer, size, true);
	if (!rc)
		rc = stub_memory(stub, request, request->data.args[4], &size,
				 sizeof(size), true);
	return rc;
}

/* Update Netlink membership/options or forward supported SOL_SOCKET settings. */
static int stub_setopt(struct connector_stub *stub,
		       const struct seccomp_notif *request,
		       struct stub_socket *item, int fd)
{
	int level = request->data.args[1], option = request->data.args[2];
	unsigned int value = 0, length = request->data.args[4];
	unsigned char buffer[256];
	size_t needed;
	int rc;

	if (level == SOL_NETLINK) {
		if (length >= sizeof(value)) {
			rc = stub_memory(stub, request, request->data.args[3],
					 &value, sizeof(value), false);
			if (rc)
				return rc;
		}
		if (option == NETLINK_ADD_MEMBERSHIP ||
		    option == NETLINK_DROP_MEMBERSHIP) {
			if (!value || value > 32)
				return -EINVAL;
			item->groups_allocated = true;
			if (option == NETLINK_ADD_MEMBERSHIP)
				item->groups |= 1U << (value - 1);
			else
				item->groups &= ~(1U << (value - 1));
			return 0;
		}
		if (!stub_netlink_option(option))
			return -ENOPROTOOPT;
		if (value)
			item->options |= 1U << option;
		else
			item->options &= ~(1U << option);
		return 0;
	}
	if (level != SOL_SOCKET)
		return -ENOPROTOOPT;
	switch (option) {
	case SO_RCVTIMEO:
	case SO_SNDTIMEO:
		needed = sizeof(struct timeval);
		break;
	case SO_LINGER:
		needed = sizeof(struct linger);
		break;
	case SO_RCVBUF:
	case SO_SNDBUF:
	case SO_RCVBUFFORCE:
	case SO_SNDBUFFORCE:
	case SO_PASSCRED:
	case SO_RCVLOWAT:
	case SO_SNDLOWAT:
	case SO_REUSEADDR:
	case SO_REUSEPORT:
	case SO_BROADCAST:
	case SO_DONTROUTE:
	case SO_KEEPALIVE:
	case SO_PRIORITY:
	case SO_OOBINLINE:
	case SO_DEBUG:
		needed = sizeof(int);
		break;
	default:
		return -ENOPROTOOPT;
	}
	if (length < needed)
		return -EINVAL;
	rc = stub_memory(stub, request, request->data.args[3], buffer, needed, false);
	if (rc)
		return rc;
	return setsockopt(fd, level, option, buffer, needed) < 0 ? -errno : 0;
}

/* Read and validate the target's iovec array and calculate its total length. */
static int stub_load_iov(struct connector_stub *stub,
			 const struct seccomp_notif *request, uint64_t pointer,
			 size_t count, struct iovec **vectors, size_t *total)
{
	size_t i;
	int rc;

	*vectors = NULL;
	*total = 0;
	if (count > IOV_MAX)
		return -EMSGSIZE;
	if (!count)
		return 0;
	*vectors = malloc(count * sizeof(**vectors));
	if (!*vectors)
		return -ENOMEM;
	rc = stub_memory(stub, request, pointer, *vectors,
			 count * sizeof(**vectors), false);
	if (rc)
		return rc;
	for (i = 0; i < count; i++) {
		if ((*vectors)[i].iov_len > (size_t)SSIZE_MAX - *total)
			return -EINVAL;
		*total += (*vectors)[i].iov_len;
	}
	return 0;
}

/* Gather or scatter target iovecs using checked cross-process memory copies. */
static int stub_copy_iov(struct connector_stub *stub,
			 const struct seccomp_notif *request,
			 const struct iovec *vectors, size_t count,
			 unsigned char *buffer, size_t total, bool write)
{
	size_t i, length, offset = 0;
	int rc;

	for (i = 0; i < count && offset < total; i++) {
		length = vectors[i].iov_len;
		if (length > total - offset)
			length = total - offset;
		rc = stub_memory(stub, request, (uintptr_t)vectors[i].iov_base,
				 buffer + offset, length, write);
		if (rc)
			return rc;
		offset += length;
	}
	return 0;
}

/* Validate a connector control message, update subscriptions, and emit ACKs. */
static int stub_registration(struct connector_stub *stub,
			      struct stub_socket *sender,
			      const unsigned char *packet, size_t length)
{
	struct nlmsghdr header;
	struct cn_msg message;
	struct stub_socket *item;
	struct socket_peer ack = { .sequence = stub->sequence };
	uint32_t operation, mask = PROC_EVENT_ALL;
	bool listening = false;
	ssize_t sent;
	int error = 0, rc;

	/* connector.c passes only the first Netlink message to the callback. */
	if (length < NLMSG_HDRLEN + sizeof(message))
		goto malformed;
	memcpy(&header, packet, sizeof(header));
	if (header.nlmsg_len < NLMSG_HDRLEN + sizeof(message) ||
	    header.nlmsg_len > length ||
	    header.nlmsg_len > CONNECTOR_INPUT_SIZE)
		goto malformed;
	memcpy(&message, packet + NLMSG_HDRLEN, sizeof(message));
	if (message.len > header.nlmsg_len - NLMSG_HDRLEN - sizeof(message))
		goto malformed;
	if (message.id.idx != CN_IDX_PROC || message.id.val != CN_VAL_PROC) {
		fprintf(stderr, "%s: connector stub ignored connector id %u:%u\n",
			stub->prog, message.id.idx, message.id.val);
		return 0;
	}
	if (message.len != sizeof(operation) && message.len != 2 * sizeof(operation))
		goto malformed;
	memcpy(&operation, packet + NLMSG_HDRLEN + sizeof(message),
	       sizeof(operation));
	if (message.len == 2 * sizeof(operation)) {
		memcpy(&mask, packet + NLMSG_HDRLEN + sizeof(message) +
		       sizeof(operation), sizeof(mask));
		mask &= PROC_EVENT_ALL;
		if (!mask)
			mask = PROC_EVENT_ALL;
	}
	sender->registered = true;
	sender->event_mask = mask;
	switch (operation) {
	case PROC_CN_MCAST_LISTEN:
		sender->listening = true;
		break;
	case PROC_CN_MCAST_IGNORE:
		sender->listening = false;
		sender->event_mask = PROC_EVENT_NONE;
		break;
	default:
		error = EINVAL;
		break;
	}
	for (item = stub->sockets; item; item = item->next)
		listening |= item->listening;
	/* The kernel suppresses ACKs after the last listener unregisters. */
	if (!listening)
		return 0;
	rc = build_connector_ack(&ack, &message, error);
	if (rc)
		return rc;
	stub->sequence = ack.sequence;
	for (item = stub->sockets; item; item = item->next) {
		if (!(item->groups & 1U) ||
		    (item->registered &&
		     (!item->listening || item->event_mask != PROC_EVENT_ALL)))
			continue;
		do {
			sent = send(item->peer, ack.output, ack.output_len,
				    MSG_DONTWAIT | MSG_NOSIGNAL);
		} while (sent < 0 && errno == EINTR);
		if (sent < 0 && (errno == EPIPE || errno == ECONNRESET))
			continue;
		if (sent < 0) {
			fprintf(stderr, "%s: connector stub dropped multicast "
				"ACK for port %u: %s\n", stub->prog,
				item->port, strerror(errno));
		} else if ((size_t)sent != ack.output_len)
			return -EIO;
	}
	return 0;
malformed:
	fprintf(stderr, "%s: connector stub discarded malformed registration\n",
		stub->prog);
	return 0;
}

/* Emulate one send or write and process its connector registration payload. */
static int64_t stub_send_one(struct connector_stub *stub,
			     const struct seccomp_notif *request,
			     struct stub_socket *item, int fd,
			     enum stub_operation operation, uint64_t header)
{
	const __u64 *args = request->data.args;
	struct msghdr message = { 0 };
	struct iovec single, *vectors = NULL;
	struct sockaddr_nl destination = {
		.nl_family = AF_NETLINK, .nl_pid = item->destination,
		.nl_groups = item->destination_group
	};
	unsigned char *buffer = NULL;
	size_t count, total;
	int flags = 0, sndbuf, rc;
	int64_t result;
	socklen_t size = sizeof(sndbuf);

	if (operation == STUB_SENDMSG || operation == STUB_SENDMMSG) {
		rc = stub_memory(stub, request, header, &message,
				 sizeof(message), false);
		if (rc)
			return rc;
		flags = args[operation == STUB_SENDMMSG ? 3 : 2];
		count = message.msg_iovlen;
		rc = stub_load_iov(stub, request, (uintptr_t)message.msg_iov,
				   count, &vectors, &total);
		if (rc) {
			result = rc;
			goto out;
		}
		if (message.msg_controllen) {
			/* Ancillary credentials are unnecessary for this test
			 * endpoint; do not pretend to support descriptor passing. */
			result = -EOPNOTSUPP;
			goto out;
		}
	} else if (operation == STUB_WRITEV) {
		count = args[2];
		rc = stub_load_iov(stub, request, args[1], count, &vectors, &total);
		if (rc) {
			result = rc;
			goto out;
		}
	} else {
		single = (struct iovec) {
			.iov_base = (void *)(uintptr_t)args[1], .iov_len = args[2]
		};
		total = single.iov_len;
		count = 1;
		if (total > SSIZE_MAX)
			return -EMSGSIZE;
		if (operation == STUB_SENDTO) {
			flags = args[3];
			message.msg_name = (void *)(uintptr_t)args[4];
			message.msg_namelen = args[5];
		}
	}
	if (flags & MSG_OOB) {
		result = -EOPNOTSUPP;
		goto out;
	}
	if (!total) {
		result = -ENODATA;
		goto out;
	}
	if (message.msg_name && message.msg_namelen) {
		rc = stub_read_address(stub, request, (uintptr_t)message.msg_name,
				       message.msg_namelen, &destination, false);
		if (rc) {
			result = rc;
			goto out;
		}
	}
	if (destination.nl_pid) {
		result = -ECONNREFUSED;
		goto out;
	}
	rc = stub_autobind(stub, request, item);
	if (rc) {
		result = rc;
		goto out;
	}
	if (getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, &size) < 0) {
		result = -errno;
		goto out;
	}
	if (sndbuf < 32 || total > (size_t)sndbuf - 32) {
		result = -EMSGSIZE;
		goto out;
	}
	buffer = malloc(total);
	if (!buffer) {
		result = -ENOMEM;
		goto out;
	}
	rc = stub_copy_iov(stub, request, vectors ? vectors : &single,
			   count, buffer, total, false);
	if (!rc)
		rc = stub_registration(stub, item, buffer, total);
	result = rc ? rc : (int64_t)total;
out:
	free(buffer);
	free(vectors);
	return result;
}

/* Handle a send/write operation or a batch of sendmmsg messages. */
static int64_t stub_send(struct connector_stub *stub,
			 const struct seccomp_notif *request,
			 struct stub_socket *item, int fd,
			 enum stub_operation operation)
{
	uint64_t pointer = request->data.args[1];
	unsigned int count = request->data.args[2], done, length;
	int64_t result;
	int rc;

	if (operation != STUB_SENDMMSG)
		return stub_send_one(stub, request, item, fd, operation, pointer);
	if (count > IOV_MAX)
		count = IOV_MAX;
	for (done = 0; done < count; done++) {
		result = stub_send_one(stub, request, item, fd, operation, pointer);
		if (result < 0)
			return done ? done : result;
		length = result;
		rc = stub_memory(stub, request,
				 pointer + offsetof(struct mmsghdr, msg_len),
				 &length, sizeof(length), true);
		if (rc)
			return done ? (int64_t)done : rc;
		pointer += sizeof(struct mmsghdr);
	}
	return done;
}

/* Write one ancillary record to the target, preserving truncation semantics. */
static int stub_cmsg(struct connector_stub *stub,
		     const struct seccomp_notif *request,
		     struct msghdr *message, size_t *used, int level, int type,
		     const void *data, size_t length)
{
	struct cmsghdr header = {
		.cmsg_len = CMSG_LEN(length), .cmsg_level = level, .cmsg_type = type
	};
	size_t available = message->msg_controllen - *used;
	uint64_t pointer = (uintptr_t)message->msg_control + *used;
	int rc;

	if (!message->msg_control || available < sizeof(header)) {
		message->msg_flags |= MSG_CTRUNC;
		return 0;
	}
	if (available < header.cmsg_len) {
		header.cmsg_len = available;
		message->msg_flags |= MSG_CTRUNC;
	}
	rc = stub_memory(stub, request, pointer, &header, sizeof(header), true);
	if (!rc)
		rc = stub_memory(stub, request, pointer + sizeof(header),
				 (void *)data, header.cmsg_len - sizeof(header), true);
	if (!rc)
		*used += CMSG_SPACE(length) < available ?
			 CMSG_SPACE(length) : available;
	return rc;
}

/* Receive queued bytes and synthesize kernel Netlink addresses and controls. */
static int64_t stub_recv_one(struct connector_stub *stub,
			     struct stub_pending *pending, uint64_t pointer,
			     int flags)
{
	const struct seccomp_notif *request = &pending->request;
	const __u64 *args = request->data.args;
	struct msghdr target = { 0 }, local = { 0 };
	struct sockaddr_nl source = {
		.nl_family = AF_NETLINK, .nl_groups = 1
	};
	struct ucred credentials = { 0 };
	struct nl_pktinfo info = { .group = CN_IDX_PROC };
	unsigned char buffer[CONNECTOR_ACK_SIZE];
	struct iovec single, output, *vectors = NULL;
	size_t count, total, copied, control_used = 0;
	socklen_t size;
	ssize_t received;
	int rc, passcred = 0;
	int64_t result;

	if (flags & MSG_OOB)
		return -EOPNOTSUPP;
	if (pending->operation == STUB_RECVFROM) {
		single = (struct iovec) {
			.iov_base = (void *)(uintptr_t)args[1], .iov_len = args[2]
		};
		total = single.iov_len;
		count = 1;
	} else {
		rc = stub_memory(stub, request, pointer, &target,
				 sizeof(target), false);
		if (rc)
			return rc;
		count = target.msg_iovlen;
		rc = stub_load_iov(stub, request, (uintptr_t)target.msg_iov,
				   count, &vectors, &total);
		if (rc) {
			result = rc;
			goto out;
		}
	}
	output = (struct iovec) {
		.iov_base = buffer, .iov_len = total < sizeof(buffer) ?
					     total : sizeof(buffer)
	};
	local.msg_iov = &output;
	local.msg_iovlen = 1;
	received = recvmsg(pending->fd, &local, flags | MSG_DONTWAIT);
	if (received < 0) {
		result = -errno;
		goto out;
	}
	copied = (size_t)received < output.iov_len ?
		 (size_t)received : output.iov_len;
	rc = stub_copy_iov(stub, request, vectors ? vectors : &single,
			   count, buffer, copied, true);
	if (rc) {
		result = rc;
		goto out;
	}
	if (pending->operation == STUB_RECVFROM) {
		if (args[4]) {
			rc = stub_write_address(stub, request, args[4], args[5],
						&source);
			if (rc) {
				result = rc;
				goto out;
			}
		}
		result = received;
		goto out;
	}
	target.msg_flags = local.msg_flags & MSG_TRUNC;
	if (target.msg_name) {
		size = target.msg_namelen < sizeof(source) ?
		       target.msg_namelen : sizeof(source);
		rc = stub_memory(stub, request, (uintptr_t)target.msg_name,
				 &source, size, true);
		if (rc) {
			result = rc;
			goto out;
		}
		target.msg_namelen = sizeof(source);
	} else
		target.msg_namelen = 0;
	if (pending->socket->options & (1U << NETLINK_PKTINFO)) {
		rc = stub_cmsg(stub, request, &target, &control_used,
			       SOL_NETLINK, NETLINK_PKTINFO, &info, sizeof(info));
		if (rc) {
			result = rc;
			goto out;
		}
	}
	size = sizeof(passcred);
	if (getsockopt(pending->fd, SOL_SOCKET, SO_PASSCRED, &passcred, &size) < 0) {
		result = -errno;
		goto out;
	}
	if (passcred) {
		rc = stub_cmsg(stub, request, &target, &control_used, SOL_SOCKET,
			       SCM_CREDENTIALS, &credentials, sizeof(credentials));
		if (rc) {
			result = rc;
			goto out;
		}
	}
	target.msg_controllen = control_used;
	rc = stub_memory(stub, request, pointer + offsetof(struct msghdr, msg_namelen),
			 &target.msg_namelen, sizeof(target.msg_namelen), true);
	if (!rc)
		rc = stub_memory(stub, request,
				 pointer + offsetof(struct msghdr, msg_controllen),
				 &target.msg_controllen, sizeof(target.msg_controllen),
				 true);
	if (!rc)
		rc = stub_memory(stub, request,
				 pointer + offsetof(struct msghdr, msg_flags),
				 &target.msg_flags, sizeof(target.msg_flags), true);
	result = rc ? rc : received;
out:
	free(vectors);
	return result;
}

/* Validate receive timeouts and initialize the pending call's deadlines. */
static int stub_deadline(struct connector_stub *stub, struct stub_pending *pending)
{
	struct timeval timeout;
	struct timespec batch;
	uint64_t now = stub_now(), delay;
	socklen_t size = sizeof(timeout);
	int rc;

	if (!now)
		return -EIO;
	if (getsockopt(pending->fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, &size) < 0)
		return -errno;
	if (timeout.tv_sec || timeout.tv_usec) {
		delay = (uint64_t)timeout.tv_sec >
			(UINT64_MAX - (uint64_t)timeout.tv_usec * 1000U) /
			1000000000U ? UINT64_MAX :
			(uint64_t)timeout.tv_sec * 1000000000U +
			(uint64_t)timeout.tv_usec * 1000U;
		pending->deadline = delay > UINT64_MAX - now ? UINT64_MAX :
				    now + delay;
	}
	if (pending->operation == STUB_RECVMMSG && pending->request.data.args[4]) {
		rc = stub_memory(stub, &pending->request, pending->request.data.args[4],
				 &batch, sizeof(batch), false);
		if (rc)
			return rc;
		if (batch.tv_sec < 0 || batch.tv_nsec < 0 || batch.tv_nsec >= 1000000000)
			return -EINVAL;
		delay = (uint64_t)batch.tv_sec >
			(UINT64_MAX - (uint64_t)batch.tv_nsec) / 1000000000U ?
			UINT64_MAX : (uint64_t)batch.tv_sec * 1000000000U +
				     batch.tv_nsec;
		delay = delay > UINT64_MAX - now ? UINT64_MAX : now + delay;
		pending->batch_deadline = delay;
		if (!pending->deadline || delay < pending->deadline) {
			pending->deadline = delay;
			pending->batch_timeout = true;
		}
	}
	return 0;
}

/* Attempt a pending receive or batch without blocking the supervisor. */
static int stub_try_receive(struct connector_stub *stub,
			    struct stub_pending *pending, int64_t *result)
{
	struct seccomp_notif *request = &pending->request;
	unsigned int length, count = 1;
	int flags, fd_flags, rc;
	uint64_t pointer = request->data.args[1], now;
	struct timespec remaining;

	flags = request->data.args[pending->operation == STUB_RECVMSG ? 2 : 3];
	if (pending->operation == STUB_RECVMMSG) {
		count = request->data.args[2];
		if (count > IOV_MAX)
			count = IOV_MAX;
		pointer += pending->completed * sizeof(struct mmsghdr);
	}
	fd_flags = fcntl(pending->fd, F_GETFL);
	if (fd_flags < 0) {
		*result = -errno;
		return 1;
	}
	while (pending->completed < count) {
		if (flags & MSG_WAITFORONE && pending->completed)
			flags |= MSG_DONTWAIT;
		*result = stub_recv_one(stub, pending, pointer, flags);
		if (*result == -EAGAIN || *result == -EWOULDBLOCK) {
			if (fd_flags & O_NONBLOCK || flags & MSG_DONTWAIT)
				break;
			now = stub_now();
			if (!now) {
				*result = -EIO;
				break;
			}
			if (pending->deadline && now >= pending->deadline) {
				if (pending->batch_timeout)
					*result = 0;
				break;
			}
			return 0;
		}
		if (*result < 0)
			break;
		if (pending->operation != STUB_RECVMMSG)
			return 1;
		length = *result;
		rc = stub_memory(stub, request,
				 pointer + offsetof(struct mmsghdr, msg_len),
				 &length, sizeof(length), true);
		if (rc) {
			*result = rc;
			break;
		}
		pending->completed++;
		pointer += sizeof(struct mmsghdr);
	}
	if (pending->operation == STUB_RECVMMSG) {
		if (pending->completed || !count)
			*result = pending->completed;
		if (request->data.args[4] && pending->batch_deadline) {
			now = stub_now();
			if (!now) {
				*result = -EIO;
				return 1;
			}
			now = pending->batch_deadline > now ?
			      pending->batch_deadline - now : 0;
			remaining.tv_sec = now / 1000000000U;
			remaining.tv_nsec = now % 1000000000U;
			rc = stub_memory(stub, request, request->data.args[4],
					 &remaining, sizeof(remaining), true);
			if (rc)
				*result = rc;
		}
	}
	return 1;
}

/* Resume queued receives and retire completed or canceled notifications. */
static int stub_process_pending(struct connector_stub *stub)
{
	struct stub_pending **link = &stub->pending, *pending;
	int64_t result = 0;
	int rc;

	while ((pending = *link)) {
		rc = stub_valid(stub, &pending->request);
		if (rc == -ENOENT) {
			*link = pending->next;
			close(pending->fd);
			free(pending);
			continue;
		}
		if (rc)
			return rc;
		if (!stub_try_receive(stub, pending, &result)) {
			link = &pending->next;
			continue;
		}
		if (stub->access_error)
			return -stub->access_error;
		rc = stub_reply(stub, &pending->request, result, false);
		*link = pending->next;
		close(pending->fd);
		free(pending);
		if (rc)
			return rc;
	}
	return 0;
}

/* Route a stub syscall to emulation or continue it for an unrelated FD. */
static int stub_dispatch(struct connector_stub *stub,
			 const struct seccomp_notif *request)
{
	struct stub_socket *item;
	struct stub_pending *pending;
	struct sockaddr_nl address = { .nl_family = AF_NETLINK };
	int operation = stub_operation(request->data.nr);
	int fd, rc;
	int64_t result = 0;

	if (operation < 0)
		return 0;
	if (operation == STUB_SOCKET) {
		if ((uint32_t)request->data.args[0] != AF_NETLINK ||
		    (uint32_t)request->data.args[2] != NETLINK_CONNECTOR)
			return 0;
		rc = stub_create(stub, request);
		return rc ? rc : 1;
	}
	fd = stub_lookup(stub, request, &item);
	if (fd < 0) {
		if (stub->access_error)
			return -stub->access_error;
		rc = stub_reply(stub, request, fd, false);
		return rc ? rc : 1;
	}
	if (!item) {
		close(fd);
		rc = stub_reply(stub, request, 0, true);
		return rc ? rc : 1;
	}
	switch (operation) {
	case STUB_BIND:
	case STUB_CONNECT:
		result = stub_bind_connect(stub, request, item,
					   operation == STUB_CONNECT);
		break;
	case STUB_SHUTDOWN:
		/* Keep the transport and subscription usable across reconfiguration. */
		result = 0;
		break;
	case STUB_GETNAME:
	case STUB_GETPEER:
		address.nl_pid = operation == STUB_GETNAME ?
				 item->port : item->destination;
		address.nl_groups = operation == STUB_GETNAME ?
				    item->groups : item->destination_group;
		result = stub_write_address(stub, request, request->data.args[1],
					     request->data.args[2], &address);
		break;
	case STUB_GETOPT:
		result = stub_getopt(stub, request, item, fd);
		break;
	case STUB_SETOPT:
		result = stub_setopt(stub, request, item, fd);
		break;
	case STUB_RECVFROM:
	case STUB_RECVMSG:
	case STUB_RECVMMSG:
		pending = calloc(1, sizeof(*pending));
		if (!pending) {
			result = -ENOMEM;
			break;
		}
		pending->request = *request;
		pending->operation = operation;
		pending->socket = item;
		pending->fd = fd;
		rc = stub_deadline(stub, pending);
		if (rc) {
			free(pending);
			result = rc;
			break;
		}
		if (!stub_try_receive(stub, pending, &result)) {
			pending->next = stub->pending;
			stub->pending = pending;
			return 1;
		}
		free(pending);
		break;
	default:
		result = stub_send(stub, request, item, fd, operation);
		break;
	}
	close(fd);
	if (stub->access_error)
		return -stub->access_error;
	rc = stub_reply(stub, request, result, false);
	return rc ? rc : 1;
}

/* Dispatch a notification to stub, socket, or signed-return handling. */
static int respond_notification(int fd, const struct configuration *config,
				const char *prog, struct socket_peer **peers,
				struct connector_stub *stub)
{
	struct seccomp_notif *request = NULL;
	struct seccomp_notif_resp *response = NULL;
	struct socket_peer *peer = NULL;
	const struct action *selected = &config->def;
	uint32_t action;
	size_t i;
	int rc, socket_fd;

	rc = seccomp_notify_alloc(&request, &response);
	if (rc)
		goto out;
	if (config->stub_connector) {
		rc = ioctl(fd, SECCOMP_IOCTL_NOTIF_RECV, request);
		if (rc < 0)
			rc = -errno;
	} else
		rc = seccomp_notify_receive(fd, request);
	if (rc)
		goto out;
	rc = seccomp_notify_id_valid(fd, request->id);
	if (rc)
		goto out;
	if (config->stub_connector) {
		rc = stub_dispatch(stub, request);
		if (rc) {
			if (rc > 0)
				rc = 0;
			goto out;
		}
	}
	for (i = 0; i < config->rule_count; i++) {
		const struct rule *rule = &config->rules[i];

		if (!rule->action.emulated)
			continue;
		rc = evaluate_bpf(rule, &request->data, &action);
		if (rc)
			goto out;
		if (action == SCMP_ACT_NOTIFY) {
			selected = &rule->action;
			break;
		}
	}
	if (i == config->rule_count && !config->def.emulated) {
		rc = -EINVAL;
		goto out;
	}
	response->id = request->id;
	if (selected->socket) {
		socket_fd = create_backing_socket(selected, &peer);
		if (socket_fd >= 0 && peer && is_proc_connector(&request->data)) {
			peer->connector = true;
			peer->input = malloc(CONNECTOR_INPUT_SIZE);
			if (!peer->input) {
				close(socket_fd);
				release_socket_peers(peer);
				peer = NULL;
				socket_fd = -ENOMEM;
			}
		}
		if (socket_fd < 0) {
			response->error = socket_fd;
			fprintf(stderr, "%s: cannot create rule socket "
				"(family=%d kind=%d protocol=%d): %s\n", prog,
				selected->family, selected->kind,
				selected->protocol, strerror(-response->error));
		} else {
			struct seccomp_notif_addfd addfd = {
				.id = request->id,
				.flags = SECCOMP_ADDFD_FLAG_SEND,
				.srcfd = socket_fd
			};

			/* Install the fd and reply together, including cancellation
			 * handling, so an abandoned call cannot leak a target fd. */
			do {
				rc = seccomp_notify_addfd(fd, &addfd);
			} while (rc == -EINTR);
			close(socket_fd);
			if (rc >= 0) {
				if (peer) {
					peer->next = *peers;
					*peers = peer;
				}
				rc = 0;
			} else
				release_socket_peers(peer);
			goto out;
		}
	} else {
		response->val = selected->value >= 0 ? selected->value : 0;
		response->error = selected->value < 0 ? selected->value : 0;
	}
	do {
		rc = seccomp_notify_respond(fd, response);
	} while (rc == -EINTR);
out:
	seccomp_notify_free(request, response);
	return rc;
}

/* Validate a connector frame and determine its registration result. */
static int parse_connector_request(const unsigned char *data, size_t size,
				   struct cn_msg *request, int *error)
{
	struct nlmsghdr header;
	uint32_t operation;

	if (size < NLMSG_HDRLEN + sizeof(*request))
		return -EPROTO;
	memcpy(&header, data, sizeof(header));
	if (header.nlmsg_len < NLMSG_HDRLEN + sizeof(*request) ||
	    header.nlmsg_len > size)
		return -EPROTO;
	if (header.nlmsg_len > CONNECTOR_INPUT_SIZE)
		return -EMSGSIZE;
	memcpy(request, data + NLMSG_HDRLEN, sizeof(*request));
	if (request->len > header.nlmsg_len - NLMSG_HDRLEN - sizeof(*request))
		return -EPROTO;
	if (request->id.idx != CN_IDX_PROC || request->id.val != CN_VAL_PROC)
		return -EOPNOTSUPP;
	*error = EINVAL;
	if (request->len == sizeof(operation) ||
	    request->len == 2 * sizeof(operation)) {
		memcpy(&operation, data + NLMSG_HDRLEN + sizeof(*request),
		       sizeof(operation));
		if (operation == PROC_CN_MCAST_LISTEN ||
		    operation == PROC_CN_MCAST_IGNORE)
			*error = 0;
	}
	return 0;
}

/* Encode a 76-byte process-connector ACK and advance its sequence counter. */
static int build_connector_ack(struct socket_peer *peer,
			       const struct cn_msg *request, int error)
{
	struct nlmsghdr header = {
		.nlmsg_len = CONNECTOR_ACK_SIZE,
		.nlmsg_type = NLMSG_DONE,
		.nlmsg_seq = peer->sequence
	};
	struct cn_msg message = {
		.id = { .idx = CN_IDX_PROC, .val = CN_VAL_PROC },
		.seq = peer->sequence,
		.ack = request->ack + 1U,
		.len = sizeof(struct proc_event)
	};
	struct proc_event event;
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
		return -errno;
	memset(&event, 0, sizeof(event));
	event.what = PROC_EVENT_NONE;
	event.timestamp_ns = (uint64_t)now.tv_sec * 1000000000U + now.tv_nsec;
	event.event_data.ack.err = error;
	/* proc_event is not naturally aligned inside the netlink packet. */
	memcpy(peer->output, &header, sizeof(header));
	memcpy(peer->output + NLMSG_HDRLEN, &message, sizeof(message));
	memcpy(peer->output + NLMSG_HDRLEN + sizeof(message), &event,
	       sizeof(event));
	peer->sequence++;
	peer->output_len = sizeof(peer->output);
	peer->output_offset = 0;
	return 0;
}

/* Send as much of a pending ACK as possible without blocking. */
static int flush_connector_ack(struct socket_peer *peer)
{
	ssize_t sent;
	size_t remaining = peer->output_len - peer->output_offset;

	if (!remaining)
		return 0;
	do {
		sent = send(peer->fd, peer->output + peer->output_offset,
			    remaining, MSG_DONTWAIT | MSG_NOSIGNAL);
	} while (sent < 0 && errno == EINTR);
	if (sent < 0)
		return errno == EAGAIN || errno == EWOULDBLOCK ? 0 : -errno;
	if (!sent)
		return -EPIPE;
	if (peer->kind != SOCK_STREAM && (size_t)sent != remaining)
		return -EIO;
	peer->output_offset += sent;
	if (peer->output_offset == peer->output_len)
		peer->output_len = peer->output_offset = 0;
	return 0;
}

/* Process a buffered connector request and send its pending ACK. */
static int service_connector_peer(struct socket_peer *peer, short events)
{
	struct nlmsghdr header;
	struct cn_msg request;
	size_t needed;
	ssize_t received;
	int rc, error;

	rc = flush_connector_ack(peer);
	if (rc || peer->output_len)
		return rc;
	if (peer->kind == SOCK_STREAM) {
		while (true) {
			needed = NLMSG_HDRLEN;
			if (peer->input_len >= NLMSG_HDRLEN) {
				memcpy(&header, peer->input, sizeof(header));
				needed = header.nlmsg_len;
				if (needed < NLMSG_HDRLEN + sizeof(request))
					return -EPROTO;
				if (needed > CONNECTOR_INPUT_SIZE)
					return -EMSGSIZE;
			}
			if (peer->input_len >= needed)
				break;
			do {
				received = recv(peer->fd,
						peer->input + peer->input_len,
						needed - peer->input_len,
						MSG_DONTWAIT);
			} while (received < 0 && errno == EINTR);
			if (received < 0)
				return errno == EAGAIN ||
				       errno == EWOULDBLOCK ? 0 : -errno;
			if (!received)
				return 1;
			peer->input_len += received;
		}
	} else {
		do {
			received = recv(peer->fd, peer->input,
					CONNECTOR_INPUT_SIZE,
					MSG_PEEK | MSG_TRUNC | MSG_DONTWAIT);
		} while (received < 0 && errno == EINTR);
		if (received < 0)
			return errno == EAGAIN || errno == EWOULDBLOCK ?
			       0 : -errno;
		if (!received)
			return events & POLLHUP ? 1 : -EPROTO;
		if (received > CONNECTOR_INPUT_SIZE)
			return -EMSGSIZE;
		peer->input_len = received;
	}
	rc = parse_connector_request(peer->input, peer->input_len,
				     &request, &error);
	if (rc)
		return rc;
	if (peer->kind != SOCK_STREAM) {
		do {
			received = recv(peer->fd, peer->input,
					CONNECTOR_INPUT_SIZE, MSG_DONTWAIT);
		} while (received < 0 && errno == EINTR);
		if (received < 0)
			return errno == EAGAIN || errno == EWOULDBLOCK ?
			       0 : -errno;
		if ((size_t)received != peer->input_len)
			return -EIO;
	}
	peer->input_len = 0;
	rc = build_connector_ack(peer, &request, error);
	return rc ? rc : flush_connector_ack(peer);
}

/* Resolve the command through PATH before loading any restrictive filter. */
static int find_executable(const char *command, char **executable)
{
	const char *path;
	char *copy, *cursor, *dir, *candidate;
	struct stat st;
	int rc = -ENOENT;

	if (strchr(command, '/')) {
		*executable = strdup(command);
		return *executable ? 0 : -ENOMEM;
	}
	path = getenv("PATH");
	if (path && !*path)
		return -ENOENT;
	copy = strdup(path ? path : "/bin:/usr/bin");
	if (!copy)
		return -ENOMEM;
	cursor = copy;
	while ((dir = strsep(&cursor, ":"))) {
		if (asprintf(&candidate, "%s%s%s", dir, *dir ? "/" : "",
			     command) < 0) {
			rc = -ENOMEM;
			break;
		}
		if (access(candidate, X_OK) == 0 &&
		    stat(candidate, &st) == 0 && !S_ISDIR(st.st_mode)) {
			*executable = candidate;
			rc = 0;
			break;
		}
		free(candidate);
	}
	free(copy);
	return rc;
}

/* Transfer the listener FD through the unfiltered helper thread's socket. */
static void *send_listener(void *opaque)
{
	struct listener_sender *sender = opaque;
	struct timespec delay = { .tv_nsec = 1000000 };
	union {
		struct cmsghdr align;
		char data[CMSG_SPACE(sizeof(int))];
	} control = { 0 };
	char byte = 'F';
	struct iovec iov = { .iov_base = &byte, .iov_len = 1 };
	struct msghdr message = {
		.msg_iov = &iov, .msg_iovlen = 1,
		.msg_control = control.data, .msg_controllen = sizeof(control)
	};
	struct cmsghdr *header;
	ssize_t sent;
	int fd;

	while ((fd = atomic_load(&sender->fd)) == -1) {
		if (nanosleep(&delay, NULL) < 0 && errno != EINTR) {
			sender->error = errno;
			return NULL;
		}
	}
	if (fd < 0)
		return NULL;
	header = CMSG_FIRSTHDR(&message);
	header->cmsg_level = SOL_SOCKET;
	header->cmsg_type = SCM_RIGHTS;
	header->cmsg_len = CMSG_LEN(sizeof(fd));
	memcpy(CMSG_DATA(header), &fd, sizeof(fd));
	do {
		sent = sendmsg(sender->channel, &message, MSG_NOSIGNAL);
	} while (sent < 0 && errno == EINTR);
	sender->error = sent == 1 ? 0 : (sent < 0 ? errno : EIO);
	return NULL;
}

/* Load the child filter, transfer its listener if needed, and exec the command. */
static _Noreturn void execute(scmp_filter_ctx filter, const char *executable,
			     char *const command[], const char *prog, int channel)
{
	struct listener_sender sender = { .channel = channel };
	pthread_t thread;
	int rc, error;

	atomic_init(&sender.fd, -1);
	if (channel >= 0) {
		/* The transfer thread must not inherit the command's filter. */
		rc = pthread_create(&thread, NULL, send_listener, &sender);
		if (rc) {
			rc = -rc;
			goto fail;
		}
	}
	rc = seccomp_load(filter);
	if (rc)
		goto fail;
	if (channel >= 0) {
		rc = seccomp_notify_fd(filter);
		if (rc < 0)
			goto fail;
		atomic_store(&sender.fd, rc);
		rc = pthread_join(thread, NULL);
		if (!rc)
			rc = sender.error;
		if (rc) {
			rc = -rc;
			goto fail;
		}
	}
	execv(executable, command);
	error = errno;
	fprintf(stderr, "%s: cannot execute '%s': %s\n",
		prog, command[0], strerror(error));
	_exit(error == ENOENT ? 127 : 126);
fail:
	atomic_store(&sender.fd, -2);
	fprintf(stderr, "%s: cannot initialize seccomp filter: %s\n",
		prog, strerror(-rc));
	_exit(1);
}

/* Forward supervisor signals to the live child while preserving errno. */
static void forward_signal(int signum)
{
	int saved_errno = errno;

	if (child_pid && kill(child_pid, signum) < 0 && errno != ESRCH)
		forward_error = errno;
	errno = saved_errno;
}

/* Wait for or poll child exit, retrying interruptions and clearing its PID. */
static int wait_child(pid_t pid, int *status, bool blocking)
{
	pid_t waited;

	do {
		waited = waitpid(pid, status, blocking ? 0 : WNOHANG);
	} while (waited < 0 && errno == EINTR);
	if (waited < 0)
		return -errno;
	if (!waited)
		return 0;
	child_pid = 0;
	return 1;
}

/* Receive and validate the child's listener FD with a bounded startup wait. */
static int receive_listener(int channel, int *listener)
{
	struct pollfd pollfd = { .fd = channel, .events = POLLIN };
	struct timespec start, now;
	int64_t remaining;
	union {
		struct cmsghdr align;
		char data[CMSG_SPACE(sizeof(int))];
	} control = { 0 };
	char byte;
	struct iovec iov = { .iov_base = &byte, .iov_len = 1 };
	struct msghdr message = {
		.msg_iov = &iov, .msg_iovlen = 1,
		.msg_control = control.data, .msg_controllen = sizeof(control)
	};
	struct cmsghdr *header;
	ssize_t received;
	int fd, count = 0, rc;
	size_t offset, size;

	if (clock_gettime(CLOCK_MONOTONIC, &start) < 0)
		return -errno;
	while (true) {
		if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
			return -errno;
		remaining = 10000 - (now.tv_sec - start.tv_sec) * 1000 -
			    (now.tv_nsec - start.tv_nsec) / 1000000;
		if (remaining <= 0)
			return -ETIMEDOUT;
		rc = poll(&pollfd, 1, remaining);
		if (rc < 0 && errno == EINTR)
			continue;
		if (rc < 0)
			return -errno;
		if (!rc)
			return -ETIMEDOUT;
		message.msg_controllen = sizeof(control);
		message.msg_flags = 0;
		received = recvmsg(channel, &message,
				   MSG_CMSG_CLOEXEC | MSG_DONTWAIT);
		if (received < 0 && (errno == EINTR || errno == EAGAIN))
			continue;
		if (received <= 0)
			return received < 0 ? -errno : 0;
		break;
	}
	for (header = CMSG_FIRSTHDR(&message); header;
	     header = CMSG_NXTHDR(&message, header)) {
		if (header->cmsg_level != SOL_SOCKET ||
		    header->cmsg_type != SCM_RIGHTS)
			continue;
		if (header->cmsg_len < CMSG_LEN(0))
			return -EINVAL;
		size = header->cmsg_len - CMSG_LEN(0);
		for (offset = 0; offset + sizeof(fd) <= size;
		     offset += sizeof(fd)) {
			memcpy(&fd, CMSG_DATA(header) + offset, sizeof(fd));
			if (!count++)
				*listener = fd;
			else
				close(fd);
		}
	}
	if (count != 1 || message.msg_flags & MSG_CTRUNC)
		return -EINVAL;
	return 1;
}

/* Run an unfiltered parent handling child status, notifications, and peers. */
static int supervise(scmp_filter_ctx filter,
		     const struct configuration *config, const char *executable,
		     char *const command[], const char *prog, int *status)
{
	struct sigaction handlers[sizeof(forwarded) / sizeof(forwarded[0])];
	struct sigaction handler = { .sa_handler = forward_signal };
	struct socket_peer *peers = NULL;
	struct socket_peer *peer, **link;
	struct connector_stub stub = {
		.prog = prog, .next_port = UINT32_MAX
	};
	struct stub_pending *pending;
	sigset_t blocked, old_mask;
	struct pollfd *pollfds = NULL;
	int channels[2], listener = -1;
	int rc, cleanup_rc, timeout;
	size_t installed = 0, i, count, peer_count;
	uint64_t now, remaining;
	pid_t pid;
	bool reaped = false;

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, channels) < 0)
		return -errno;
	sigemptyset(&blocked);
	for (i = 0; i < sizeof(forwarded) / sizeof(forwarded[0]); i++)
		sigaddset(&blocked, forwarded[i]);
	if (sigprocmask(SIG_BLOCK, &blocked, &old_mask) < 0) {
		rc = -errno;
		close(channels[0]);
		close(channels[1]);
		return rc;
	}
	pid = fork();
	if (pid < 0) {
		rc = -errno;
		close(channels[0]);
		close(channels[1]);
		sigprocmask(SIG_SETMASK, &old_mask, NULL);
		return rc;
	}
	if (!pid) {
		/* Keep fd 0 occupied: libseccomp does not retain listener fd 0.
		 * Both channel ends are closed automatically by exec. */
		if (sigprocmask(SIG_SETMASK, &old_mask, NULL) < 0) {
			fprintf(stderr, "%s: cannot restore signal mask: %s\n",
				prog, strerror(errno));
			_exit(1);
		}
		execute(filter, executable, command, prog, channels[1]);
	}
	close(channels[1]);
	child_pid = pid;
	handler.sa_mask = blocked;
	for (i = 0; i < sizeof(forwarded) / sizeof(forwarded[0]); i++) {
		if (sigaction(forwarded[i], &handler, &handlers[i]) < 0) {
			rc = -errno;
			goto out;
		}
		installed++;
	}
	if (sigprocmask(SIG_SETMASK, &old_mask, NULL) < 0) {
		rc = -errno;
		goto out;
	}
	rc = receive_listener(channels[0], &listener);
	if (rc < 0)
		goto out;
	if (!rc) {
		rc = wait_child(pid, status, true);
		reaped = rc == 1;
		goto out;
	}
	close(channels[0]);
	channels[0] = -1;
	stub.listener = listener;
	while (true) {
		if (forward_error) {
			rc = -forward_error;
			goto out;
		}
		rc = wait_child(pid, status, false);
		if (rc) {
			reaped = rc == 1;
			goto out;
		}
		if (config->stub_connector) {
			rc = stub_process_pending(&stub);
			if (rc)
				goto out;
			rc = stub_prune(&stub);
			if (rc)
				goto out;
		}
		count = 1;
		for (peer = peers; peer; peer = peer->next) {
			if (peer->connector)
				count++;
		}
		peer_count = count;
		for (pending = stub.pending; pending; pending = pending->next)
			count++;
		free(pollfds);
		pollfds = calloc(count, sizeof(*pollfds));
		if (!pollfds) {
			rc = -ENOMEM;
			goto out;
		}
		pollfds[0].fd = listener;
		pollfds[0].events = POLLIN;
		i = 1;
		for (peer = peers; peer; peer = peer->next) {
			if (!peer->connector)
				continue;
			pollfds[i].fd = peer->fd;
			pollfds[i++].events = peer->output_len ?
					     POLLOUT : POLLIN;
		}
		timeout = 100;
		now = stub_now();
		if (!now) {
			rc = -EIO;
			goto out;
		}
		for (pending = stub.pending; pending; pending = pending->next) {
			pollfds[i].fd = pending->fd;
			pollfds[i++].events = POLLIN;
			if (!pending->deadline)
				continue;
			remaining = pending->deadline > now ?
				    pending->deadline - now : 0;
			if (remaining / 1000000U < (unsigned int)timeout)
				timeout = remaining / 1000000U;
		}
		rc = poll(pollfds, count, timeout);
		if (rc < 0 && errno == EINTR)
			continue;
		if (rc < 0) {
			rc = -errno;
			goto out;
		}
		if (!rc)
			continue;
		if (pollfds[0].revents & POLLIN) {
			rc = respond_notification(listener, config, prog, &peers,
						  &stub);
			if (rc && rc != -ENOENT && rc != -EINTR)
				goto out;
		} else if (pollfds[0].revents & POLLHUP) {
			rc = wait_child(pid, status, true);
			reaped = rc == 1;
			goto out;
		} else if (pollfds[0].revents & (POLLERR | POLLNVAL)) {
			rc = -EIO;
			goto out;
		}
		for (i = 1; i < peer_count; i++) {
			if (!pollfds[i].revents)
				continue;
			for (link = &peers; *link; link = &(*link)->next) {
				if ((*link)->fd == pollfds[i].fd)
					break;
			}
			if (!*link) {
				rc = -EFAULT;
				goto out;
			}
			peer = *link;
			if (pollfds[i].revents & (POLLIN | POLLOUT))
				rc = service_connector_peer(peer,
							    pollfds[i].revents);
			else
				rc = 1;
			if (rc == -EPROTO || rc == -EMSGSIZE ||
			    rc == -EOPNOTSUPP) {
				fprintf(stderr, "%s: connector peer %d: %s; "
					"leaving unrecognized traffic buffered\n",
					prog, peer->fd, strerror(-rc));
				peer->connector = false;
			} else if (rc) {
				if (rc < 0 && rc != -EPIPE &&
				    rc != -ECONNRESET)
					fprintf(stderr, "%s: connector peer %d: "
						"%s\n", prog, peer->fd,
						strerror(-rc));
				*link = peer->next;
				peer->next = NULL;
				release_socket_peers(peer);
			}
		}
	}
out:
	free(pollfds);
	if (channels[0] >= 0)
		close(channels[0]);
	if (listener >= 0)
		close(listener);
	if (!reaped) {
		if (kill(pid, SIGKILL) < 0 && errno != ESRCH) {
			fprintf(stderr, "%s: cannot terminate command: %s\n",
				prog, strerror(errno));
			cleanup_rc = wait_child(pid, status, false);
		} else
			cleanup_rc = wait_child(pid, status, true);
		if (cleanup_rc < 0)
			fprintf(stderr, "%s: cannot reap command: %s\n",
				prog, strerror(-cleanup_rc));
	}
	child_pid = 0;
	stub_release(&stub);
	release_socket_peers(peers);
	for (i = 0; i < installed; i++) {
		if (sigaction(forwarded[i], &handlers[i], NULL) < 0) {
			rc = -errno;
			fprintf(stderr, "%s: cannot restore signal handler: %s\n",
				prog, strerror(-rc));
		}
	}
	if (sigprocmask(SIG_SETMASK, &old_mask, NULL) < 0)
		rc = -errno;
	return rc < 0 ? rc : 0;
}

/* Parse the CLI, build filters, and execute or supervise the wrapped command. */
int main(int argc, char *argv[])
{
	static const struct option options[] = {
		{ "help", no_argument, NULL, 'h' },
		{ "default-action", required_argument, NULL, 'd' },
		{ "rule", required_argument, NULL, 'r' },
		{ "arch", required_argument, NULL, 'a' },
		{ "stub-netlink-connector", no_argument, NULL, 256 },
		{ NULL, 0, NULL, 0 }
	};
	const char *default_text = "allow";
	const char *prog = argv[0];
	struct configuration config = { 0 };
	scmp_filter_ctx filter = NULL;
	char **arch_names = NULL, *executable = NULL, *name, *p;
	bool emulated, plain_notify;
	int opt, rc, status = 0, result = 1;
	size_t i;
	sigset_t unblocked;

	arch_names = calloc(argc, sizeof(*arch_names));
	config.arches = calloc(argc, sizeof(*config.arches));
	config.rules = calloc(argc, sizeof(*config.rules));
	if (!arch_names || !config.arches || !config.rules) {
		fprintf(stderr, "%s: out of memory\n", prog);
		goto out;
	}
	opterr = 0;
	while ((opt = getopt_long(argc, argv, "+hd:r:a:", options, NULL)) != -1) {
		if (optarg && argv[optind - 1][0] == '-' &&
		    argv[optind - 1][1] == opt &&
		    argv[optind - 1][2] == '=' &&
		    optarg == argv[optind - 1] + 2)
			optarg++;
		switch (opt) {
		case 'h':
			usage(stdout, prog, true);
			result = 0;
			goto out;
		case 'd':
			default_text = optarg;
			break;
		case 'r':
			config.rules[config.rule_count++].text = optarg;
			break;
		case 'a':
			arch_names[config.arch_count++] = optarg;
			break;
		case 256:
			config.stub_connector = true;
			break;
		default:
			usage(stderr, prog, false);
			fprintf(stderr, "%s: invalid or incomplete option\n", prog);
			result = 2;
			goto out;
		}
	}
	if (optind >= argc) {
		usage(stderr, prog, false);
		fprintf(stderr, "%s: a command is required after --\n", prog);
		result = 2;
		goto out;
	}
	rc = parse_action(default_text, &config.def);
	if (rc) {
		fprintf(stderr, "%s: invalid default action '%s': %s\n",
			prog, default_text, strerror(-rc));
		result = 2;
		goto out;
	}
	for (i = 0; i < config.arch_count; i++) {
		name = strdup(arch_names[i]);
		if (!name) {
			fprintf(stderr, "%s: out of memory\n", prog);
			goto out;
		}
		for (p = name; *p; p++)
			*p = tolower((unsigned char)*p);
		config.arches[i] = !strcmp(name, "native") ?
				  seccomp_arch_native() :
				  seccomp_arch_resolve_name(name);
		free(name);
		if (!config.arches[i]) {
			fprintf(stderr, "%s: invalid architecture '%s'\n",
				prog, arch_names[i]);
			result = 2;
			goto out;
		}
		if (config.stub_connector &&
		    config.arches[i] != seccomp_arch_native()) {
			fprintf(stderr, "%s: connector stub requires the native "
				"syscall ABI\n", prog);
			result = 2;
			goto out;
		}
	}
	if (config.stub_connector && config.def.code != SCMP_ACT_ALLOW) {
		fprintf(stderr, "%s: connector stub requires default action allow\n",
			prog);
		result = 2;
		goto out;
	}
	rc = create_filter(config.def.code, &config, &filter);
	if (rc) {
		fprintf(stderr, "%s: cannot create filter: %s\n",
			prog, strerror(-rc));
		result = 2;
		goto out;
	}
	if (config.stub_connector) {
		rc = configure_connector_stub(filter);
		if (rc) {
			fprintf(stderr, "%s: cannot configure connector stub "
				"(native direct syscalls and Linux 6.9+ required): "
				"%s\n", prog, strerror(-rc));
			goto out;
		}
	}
	emulated = config.def.emulated || config.stub_connector;
	plain_notify = !emulated && config.def.code == SCMP_ACT_NOTIFY;
	for (i = 0; i < config.rule_count; i++) {
		struct rule *rule = &config.rules[i];

		rc = parse_rule(rule);
		if (!rc && config.stub_connector && stub_operation(rule->syscall) >= 0) {
			fprintf(stderr, "%s: rule '%s' conflicts with automatic "
				"connector-stub handling\n", prog, rule->text);
			result = 2;
			goto out;
		}
		if (!rc)
			rc = add_rule(filter, rule, &config);
		if (rc) {
			fprintf(stderr, "%s: invalid rule '%s': %s\n",
				prog, rule->text, strerror(-rc));
			result = 2;
			goto out;
		}
		emulated |= rule->action.emulated;
		plain_notify |= !rule->action.emulated &&
				rule->action.code == SCMP_ACT_NOTIFY;
	}
	if (emulated && plain_notify) {
		fprintf(stderr, "%s: plain notify cannot be combined with "
			"emulated returns\n", prog);
		result = 2;
		goto out;
	}
	rc = find_executable(argv[optind], &executable);
	if (rc) {
		fprintf(stderr, "%s: command not found or not executable: %s "
			"(%s)\n", prog, argv[optind], strerror(-rc));
		result = rc == -ENOENT ? 127 : 1;
		goto out;
	}
	/* Python ignores these signals and exec preserves that disposition. */
	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR ||
	    signal(SIGXFSZ, SIG_IGN) == SIG_ERR) {
		fprintf(stderr, "%s: cannot configure signals: %s\n",
			prog, strerror(errno));
		goto out;
	}
	if (!emulated)
		execute(filter, executable, &argv[optind], prog, -1);
	rc = supervise(filter, &config, executable, &argv[optind], prog, &status);
	if (rc) {
		fprintf(stderr, "%s: supervisor failed: %s\n", prog, strerror(-rc));
		if (rc == -ETIMEDOUT)
			fprintf(stderr, "The filter may block wrapper "
				"initialization syscalls.\n");
		goto out;
	}
	if (WIFSIGNALED(status)) {
		int signum = WTERMSIG(status);

		if (signum != SIGKILL && signal(signum, SIG_DFL) == SIG_ERR) {
			fprintf(stderr, "%s: cannot restore terminating signal: "
				"%s\n", prog, strerror(errno));
			goto out;
		}
		sigemptyset(&unblocked);
		sigaddset(&unblocked, signum);
		if (sigprocmask(SIG_UNBLOCK, &unblocked, NULL) < 0 ||
		    kill(getpid(), signum) < 0) {
			fprintf(stderr, "%s: cannot propagate terminating signal: "
				"%s\n", prog, strerror(errno));
			goto out;
		}
		_exit(128 + signum);
	}
	result = WEXITSTATUS(status);
out:
	seccomp_release(filter);
	for (i = 0; i < config.rule_count; i++)
		free(config.rules[i].program);
	free(config.rules);
	free(config.arches);
	free(arch_names);
	free(executable);
	return result;
}
