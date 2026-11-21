/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_ENGKR_TRACER_H
#define _LINUX_ENGKR_TRACER_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/atomic.h>
#include <linux/compiler.h>
#else
#include <stdint.h>
typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;
typedef int32_t s32;
#endif

/* Magic prctl option: ASCII "ENGK" */
#define PR_ENGKR_TRACER		0x454E474B

/* Subcommands passed in prctl arg2 */
#define ENGKR_CMD_ENABLE	1
#define ENGKR_CMD_DISABLE	2
#define ENGKR_CMD_RESET		3
#define ENGKR_CMD_SET_PKG	4
#define ENGKR_CMD_ADD_UID	5
#define ENGKR_CMD_CLEAR_UIDS	6
#define ENGKR_CMD_MARKER	7
#define ENGKR_CMD_READ_RING	8
#define ENGKR_CMD_GET_STATS	9
#define ENGKR_CMD_SET_FSID	10
#define ENGKR_CMD_SET_GW_MAC	11

#define ENGKR_MAX_UIDS		8
#define ENGKR_PKG_MAX		128
#define ENGKR_COMM_MAX		16
#define ENGKR_PATH_MAX		224
#define ENGKR_EXTRA_MAX		512
#define ENGKR_MARKER_MAX	192

/* Event types */
enum engkr_evt_type {
	EVT_MARKER		= 1,
	EVT_AUTO_UID_LOCK	= 2,
	EVT_OPEN		= 3,
	EVT_FACCESSAT		= 4,
	EVT_STAT		= 5,
	EVT_STATFS		= 6,
	EVT_READLINK		= 7,
	EVT_READDIR		= 8,
	EVT_UNLINK		= 9,
	EVT_RENAME		= 10,
	EVT_MKDIR		= 11,
	EVT_GETXATTR		= 12,
	EVT_SETXATTR		= 13,
	EVT_MMAP		= 14,
	EVT_EXECVE		= 15,
	EVT_UNAME		= 16,
	EVT_PTRACE		= 17,
	/* Phase 3 Deep Telemetry */
	EVT_BINDER_TX		= 18,
	EVT_BINDER_REPLY	= 19,
	EVT_IOCTL		= 20,
	EVT_NETLINK		= 21,
	EVT_TCP_CONNECT		= 22,
	EVT_UDP_SEND		= 23,
	EVT_UNIX_CONNECT	= 24,
};

/*
 * Fixed-size 784-byte binary event record (8-byte aligned, zero padding holes):
 * 8 + 4 + 4 + 4 + 2 + 2 + 4 + 4 + 16 + 224 + 512 = 784 bytes
 */
struct engkr_event {
	u64 ts_ns;
	u32 pid;
	u32 tgid;
	u32 uid;
	u16 type;
	u16 flags;
	s32 ret;
	s32 aux;
	char comm[ENGKR_COMM_MAX];
	char path[ENGKR_PATH_MAX];
	char extra[ENGKR_EXTRA_MAX];
};

/* Control & telemetry snapshot returned by ENGKR_CMD_GET_STATS */
struct engkr_stats {
	u32 active;
	u32 uid_count;
	u32 uids[ENGKR_MAX_UIDS];
	u64 total_events;
	u64 dropped_events;
	u64 ring_used_bytes;
	u64 ring_size_bytes;
	char target_pkg[ENGKR_PKG_MAX];
};

#ifdef __KERNEL__

struct file;
struct path;
struct dentry;
struct kstatfs;
struct sk_buff;
struct task_struct;
struct sockaddr;
struct in6_addr;

extern atomic_t engkr_tracer_active;
extern atomic_t engkr_fsid_enabled;
extern atomic_t engkr_gw_mac_enabled;

static inline bool engkr_tracer_is_active(void)
{
	return unlikely(atomic_read(&engkr_tracer_active) != 0);
}

bool engkr_is_current_uid_tracked(void);

/* Control interface (always callable even when inactive) */
bool engkr_handle_prctl(int option, unsigned long arg2, unsigned long arg3,
			unsigned long arg4, unsigned long arg5, long *ret);

/* Phase 3 P3 out-of-line kernel stealth spoofers */
void __engkr_spoof_statfs_fsid(struct dentry *dentry, struct kstatfs *buf);
void __engkr_spoof_neigh_lladdr(struct sk_buff *skb, u8 *lladdr, size_t addr_len);

/* Phase 2 out-of-line hook implementations */
void __engkr_trace_chown(const struct path *path, uid_t user, int error);
void __engkr_trace_open_ok(struct file *f, int flags, int fd);
void __engkr_trace_open_err(const char *name, int flags, int err);
void __engkr_trace_faccessat(const char __user *filename, int mode, int res);
void __engkr_trace_stat(const char __user *filename, int flag, int error);
void __engkr_trace_statfs(struct path *path);
void __engkr_trace_readlink(struct path *path, int ret);
void __engkr_trace_readdir(struct file *file);
void __engkr_trace_unlink(const char *name, int error);
void __engkr_trace_rename(const char *oldname, const char *newname, int error);
void __engkr_trace_mkdir(struct path *parent, struct dentry *dentry,
			 umode_t mode, int error);
void __engkr_trace_xattr(bool is_set, struct dentry *d, const char *kname,
			 const void *kvalue, ssize_t res);
void __engkr_trace_mmap(struct file *file, unsigned long len,
			unsigned long prot, unsigned long flags);
void __engkr_trace_execve(const char *filename, const char *argv_str);
void __engkr_trace_uname(void);
void __engkr_trace_ptrace(long request, long pid);

/* Phase 3 out-of-line hook implementations */
void __engkr_trace_binder(int reply, struct task_struct *peer_tsk, u32 code,
			  u32 bflags, const void __user *ubuf,
			  size_t data_size);
void __engkr_trace_ioctl(struct file *filp, unsigned int cmd,
			 unsigned long arg, bool is_compat);
void __engkr_trace_netlink(int protocol, u16 nlmsg_type, u16 nlmsg_flags,
			   size_t len);
void __engkr_trace_tcp_connect(const struct sockaddr *uaddr, int addr_len);
void __engkr_trace_udp4_send(__be32 daddr, __be16 dport, size_t len);
void __engkr_trace_udp6_send(const struct in6_addr *daddr, __be16 dport,
			     size_t len);
void __engkr_trace_unix_connect(const struct sockaddr *uaddr, int addr_len);

/* Single-instruction fast-path inline wrappers (Phase 2) */
static inline void engkr_trace_chown(const struct path *path, uid_t user, int error)
{
	if (likely(!atomic_read(&engkr_tracer_active)))
		return;
	__engkr_trace_chown(path, user, error);
}

static inline void engkr_trace_open_ok(struct file *f, int flags, int fd)
{
	if (likely(!atomic_read(&engkr_tracer_active)))
		return;
	__engkr_trace_open_ok(f, flags, fd);
}

static inline void engkr_trace_open_err(const char *name, int flags, int err)
{
	if (likely(!atomic_read(&engkr_tracer_active)))
		return;
	__engkr_trace_open_err(name, flags, err);
}

static inline void engkr_trace_faccessat(const char __user *filename,
					 int mode, int res)
{
	if (likely(!atomic_read(&engkr_tracer_active)))
		return;
	__engkr_trace_faccessat(filename, mode, res);
}

static inline void engkr_trace_stat(const char __user *filename,
				    int flag, int error)
{
	if (likely(!atomic_read(&engkr_tracer_active)))
		return;
	__engkr_trace_stat(filename, flag, error);
}

static inline void engkr_trace_statfs(struct path *path)
{
	if (likely(!atomic_read(&engkr_tracer_active)))
		return;
	__engkr_trace_statfs(path);
}

static inline void engkr_trace_readlink(struct path *path, int ret)
{
	if (likely(!atomic_read(&engkr_tracer_active)))
		return;
	__engkr_trace_readlink(path, ret);
}

static inline void engkr_trace_readdir(struct file *file)
{
	if (likely(!atomic_read(&engkr_tracer_active)))
		return;
	__engkr_trace_readdir(file);
}

static inline void engkr_trace_unlink(const char *name, int error)
{
	if (likely(!atomic_read(&engkr_tracer_active)))
		return;
	__engkr_trace_unlink(name, error);
}

static inline void engkr_trace_rename(const char *oldname,
				      const char *newname, int error)
{
	if (likely(!atomic_read(&engkr_tracer_active)))
		return;
	__engkr_trace_rename(oldname, newname, error);
}

static inline void engkr_trace_mkdir(struct path *parent,
				     struct dentry *dentry,
				     umode_t mode, int error)
{
	if (likely(!atomic_read(&engkr_tracer_active)))
		return;
	__engkr_trace_mkdir(parent, dentry, mode, error);
}

static inline void engkr_trace_xattr(bool is_set, struct dentry *d,
				     const char *kname, const void *kvalue,
				     ssize_t res)
{
	if (likely(!atomic_read(&engkr_tracer_active)))
		return;
	__engkr_trace_xattr(is_set, d, kname, kvalue, res);
}

static inline void engkr_trace_mmap(struct file *file, unsigned long len,
				    unsigned long prot, unsigned long flags)
{
	if (likely(!atomic_read(&engkr_tracer_active)))
		return;
	if (!file)
		return;
	__engkr_trace_mmap(file, len, prot, flags);
}

static inline void engkr_trace_execve(const char *filename,
				      const char *argv_str)
{
	if (likely(!atomic_read(&engkr_tracer_active)))
		return;
	__engkr_trace_execve(filename, argv_str);
}

static inline void engkr_trace_uname(void)
{
	if (likely(!atomic_read(&engkr_tracer_active)))
		return;
	__engkr_trace_uname();
}

static inline void engkr_trace_ptrace(long request, long pid)
{
	if (likely(!atomic_read(&engkr_tracer_active)))
		return;
	__engkr_trace_ptrace(request, pid);
}

/* Single-instruction fast-path inline wrappers (Phase 3) */
static inline void engkr_trace_binder(int reply, struct task_struct *peer_tsk,
				      u32 code, u32 bflags,
				      const void __user *ubuf,
				      size_t data_size)
{
	if (likely(!atomic_read(&engkr_tracer_active)))
		return;
	__engkr_trace_binder(reply, peer_tsk, code, bflags, ubuf, data_size);
}

static inline void engkr_trace_ioctl(struct file *filp, unsigned int cmd,
				     unsigned long arg, bool is_compat)
{
	if (likely(!atomic_read(&engkr_tracer_active)))
		return;
	__engkr_trace_ioctl(filp, cmd, arg, is_compat);
}

static inline void engkr_trace_netlink(int protocol, u16 nlmsg_type,
				       u16 nlmsg_flags, size_t len)
{
	if (likely(!atomic_read(&engkr_tracer_active)))
		return;
	__engkr_trace_netlink(protocol, nlmsg_type, nlmsg_flags, len);
}

static inline void engkr_trace_tcp_connect(const struct sockaddr *uaddr,
					   int addr_len)
{
	if (likely(!atomic_read(&engkr_tracer_active)))
		return;
	__engkr_trace_tcp_connect(uaddr, addr_len);
}

static inline void engkr_trace_udp4_send(__be32 daddr, __be16 dport,
					 size_t len)
{
	if (likely(!atomic_read(&engkr_tracer_active)))
		return;
	__engkr_trace_udp4_send(daddr, dport, len);
}

static inline void engkr_trace_udp6_send(const struct in6_addr *daddr,
					 __be16 dport, size_t len)
{
	if (likely(!atomic_read(&engkr_tracer_active)))
		return;
	__engkr_trace_udp6_send(daddr, dport, len);
}

static inline void engkr_trace_unix_connect(const struct sockaddr *uaddr,
					    int addr_len)
{
	if (likely(!atomic_read(&engkr_tracer_active)))
		return;
	__engkr_trace_unix_connect(uaddr, addr_len);
}

/* Single-instruction fast-path inline wrappers (Phase 3 P3 Kernel Stealth) */
static inline void engkr_spoof_statfs_fsid(struct dentry *dentry,
					   struct kstatfs *buf)
{
	if (likely(!atomic_read(&engkr_fsid_enabled)))
		return;
	__engkr_spoof_statfs_fsid(dentry, buf);
}

static inline void engkr_spoof_neigh_lladdr(struct sk_buff *skb, u8 *lladdr,
					    size_t addr_len)
{
	if (likely(!atomic_read(&engkr_gw_mac_enabled)))
		return;
	__engkr_spoof_neigh_lladdr(skb, lladdr, addr_len);
}

#endif /* __KERNEL__ */
#endif /* _LINUX_ENGKR_TRACER_H */
