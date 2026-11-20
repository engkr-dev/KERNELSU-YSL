/* SPDX-License-Identifier: GPL-2.0 */
/*
 * engkr_tracer - Phase 2 + Phase 3 Full Deep Telemetry Engine
 * Target: Android Linux 4.9.262 (Xiaomi Redmi S2 / ysl)
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/atomic.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/string.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/un.h>
#include <linux/engkr_tracer.h>

/* 16 MiB ring buffer rounded down to an integer multiple of struct engkr_event */
#define ENGKR_RING_TARGET_BYTES	(16U * 1024U * 1024U)
#define ENGKR_RING_CAPACITY	(ENGKR_RING_TARGET_BYTES / sizeof(struct engkr_event))
#define ENGKR_RING_SIZE_BYTES	(ENGKR_RING_CAPACITY * sizeof(struct engkr_event))
#define ENGKR_PATH_BUF_SZ	512
#define ENGKR_BINDER_CAPTURE_SZ	512
#define ENGKR_READ_CHUNK_EVTS	8

atomic_t engkr_tracer_active = ATOMIC_INIT(0);
EXPORT_SYMBOL(engkr_tracer_active);

static DEFINE_MUTEX(engkr_ctrl_mutex);
static DEFINE_SPINLOCK(engkr_ring_lock);

static struct engkr_event *engkr_ring;
static u32 engkr_ring_head;
static u32 engkr_ring_tail;
static u32 engkr_ring_count;
static u64 engkr_total_events;
static u64 engkr_dropped_events;

static u32 engkr_target_uids[ENGKR_MAX_UIDS];
static u32 engkr_uid_count;
static char engkr_target_pkg[ENGKR_PKG_MAX];

static bool engkr_uid_matches_locked(u32 uid)
{
	u32 i;

	for (i = 0; i < engkr_uid_count; i++) {
		if (engkr_target_uids[i] == uid)
			return true;
	}
	return false;
}

static bool engkr_uid_matches(u32 uid)
{
	unsigned long flags;
	bool match;

	spin_lock_irqsave(&engkr_ring_lock, flags);
	match = engkr_uid_matches_locked(uid);
	spin_unlock_irqrestore(&engkr_ring_lock, flags);
	return match;
}

bool engkr_is_current_uid_tracked(void)
{
	if (likely(!atomic_read(&engkr_tracer_active)))
		return false;
	return engkr_uid_matches(current_uid().val);
}
EXPORT_SYMBOL(engkr_is_current_uid_tracked);

static bool engkr_has_target_pkg(void)
{
	return READ_ONCE(engkr_target_pkg[0]) != '\0';
}

static bool engkr_path_matches(const char *path)
{
	unsigned long flags;
	bool match = false;

	if (!path || !path[0] || !engkr_has_target_pkg())
		return false;

	spin_lock_irqsave(&engkr_ring_lock, flags);
	if (engkr_target_pkg[0])
		match = (strstr(path, engkr_target_pkg) != NULL);
	spin_unlock_irqrestore(&engkr_ring_lock, flags);
	return match;
}

static bool engkr_add_uid_internal(u32 uid)
{
	unsigned long flags;
	bool added = false;

	spin_lock_irqsave(&engkr_ring_lock, flags);
	if (!engkr_uid_matches_locked(uid) && engkr_uid_count < ENGKR_MAX_UIDS) {
		engkr_target_uids[engkr_uid_count++] = uid;
		added = true;
	}
	spin_unlock_irqrestore(&engkr_ring_lock, flags);
	return added;
}

static void engkr_init_event(struct engkr_event *ev, u16 type, u16 flags,
			     s32 ret, s32 aux)
{
	memset(ev, 0, sizeof(*ev));
	ev->ts_ns = local_clock();
	ev->pid = (u32)current->pid;
	ev->tgid = (u32)current->tgid;
	ev->uid = current_uid().val;
	ev->type = type;
	ev->flags = flags;
	ev->ret = ret;
	ev->aux = aux;
	get_task_comm(ev->comm, current);
}

static void engkr_ring_push(const struct engkr_event *ev)
{
	unsigned long flags;

	spin_lock_irqsave(&engkr_ring_lock, flags);
	if (unlikely(!engkr_ring)) {
		engkr_dropped_events++;
		spin_unlock_irqrestore(&engkr_ring_lock, flags);
		return;
	}
	if (unlikely(engkr_ring_count >= ENGKR_RING_CAPACITY)) {
		engkr_dropped_events++;
		spin_unlock_irqrestore(&engkr_ring_lock, flags);
		return;
	}
	memcpy(&engkr_ring[engkr_ring_head], ev, sizeof(*ev));
	engkr_ring_head++;
	if (engkr_ring_head >= ENGKR_RING_CAPACITY)
		engkr_ring_head = 0;
	engkr_ring_count++;
	engkr_total_events++;
	spin_unlock_irqrestore(&engkr_ring_lock, flags);
}

static char *engkr_resolve_path(const struct path *path, char *buf, int buflen)
{
	char *p;

	if (!path || !path->dentry || !path->mnt)
		return NULL;
	p = d_path(path, buf, buflen);
	if (IS_ERR(p))
		return NULL;
	return p;
}

static inline bool engkr_is_printable(unsigned char c)
{
	return (c >= 0x20 && c <= 0x7E);
}

/*
 * Parse Android Binder Parcel bytes (UTF-16LE + ASCII runs >= 3 chars)
 * into ev->extra, prefixed with raw parcel size.
 */
static void engkr_parse_binder_parcel(char *out, size_t out_sz,
				      const unsigned char *buf,
				      size_t copy_len, size_t total_len)
{
	size_t pos;
	size_t i = 0;

	pos = (size_t)scnprintf(out, out_sz, "sz=%zu", total_len);
	if (!buf || copy_len == 0)
		return;

	while (i < copy_len && pos + 6 < out_sz) {
		/* Check UTF-16LE printable ASCII run (>= 3 chars) */
		if (i + 5 < copy_len &&
		    engkr_is_printable(buf[i]) && buf[i + 1] == 0x00) {
			size_t j = i;
			size_t chars = 0;

			while (j + 1 < copy_len &&
			       engkr_is_printable(buf[j]) &&
			       buf[j + 1] == 0x00) {
				chars++;
				j += 2;
			}
			if (chars >= 3) {
				size_t k;

				pos += (size_t)scnprintf(out + pos,
							 out_sz - pos, " | ");
				for (k = i; k < j && pos + 1 < out_sz; k += 2)
					out[pos++] = (char)buf[k];
				out[pos] = '\0';
				i = j;
				continue;
			}
		}

		/* Check raw ASCII printable run (>= 3 chars) */
		if (engkr_is_printable(buf[i])) {
			size_t j = i;

			while (j < copy_len && engkr_is_printable(buf[j]))
				j++;
			if (j - i >= 3) {
				size_t k;

				pos += (size_t)scnprintf(out + pos,
							 out_sz - pos, " | ");
				for (k = i; k < j && pos + 1 < out_sz; k++)
					out[pos++] = (char)buf[k];
				out[pos] = '\0';
				i = j;
				continue;
			}
			i = j;
			continue;
		}
		i++;
	}
}

/* ==================== Control Plane (prctl) ==================== */

static long engkr_cmd_read_ring(void __user *ubuf, unsigned long max_bytes)
{
	struct engkr_event *chunk;
	unsigned long copied = 0;
	unsigned long max_evts;

	if (!ubuf || max_bytes < sizeof(struct engkr_event))
		return 0;

	max_evts = max_bytes / sizeof(struct engkr_event);
	chunk = kmalloc(ENGKR_READ_CHUNK_EVTS * sizeof(*chunk), GFP_KERNEL);
	if (!chunk)
		return -ENOMEM;

	while (max_evts > 0) {
		unsigned long flags;
		u32 batch = 0;
		u32 want = (max_evts > ENGKR_READ_CHUNK_EVTS) ?
			   ENGKR_READ_CHUNK_EVTS : (u32)max_evts;

		spin_lock_irqsave(&engkr_ring_lock, flags);
		if (engkr_ring) {
			while (batch < want && engkr_ring_count > 0) {
				memcpy(&chunk[batch],
				       &engkr_ring[engkr_ring_tail],
				       sizeof(*chunk));
				engkr_ring_tail++;
				if (engkr_ring_tail >= ENGKR_RING_CAPACITY)
					engkr_ring_tail = 0;
				engkr_ring_count--;
				batch++;
			}
		}
		spin_unlock_irqrestore(&engkr_ring_lock, flags);

		if (batch == 0)
			break;

		if (copy_to_user((char __user *)ubuf + copied, chunk,
				 batch * sizeof(*chunk))) {
			kfree(chunk);
			return copied ? (long)copied : -EFAULT;
		}
		copied += batch * sizeof(*chunk);
		max_evts -= batch;
	}

	kfree(chunk);
	return (long)copied;
}

bool engkr_handle_prctl(int option, unsigned long arg2, unsigned long arg3,
			unsigned long arg4, unsigned long arg5, long *ret)
{
	unsigned long flags;

	if (likely(option != PR_ENGKR_TRACER))
		return false;

	if (!uid_eq(current_euid(), GLOBAL_ROOT_UID))
		return false;

	switch (arg2) {
	case ENGKR_CMD_ENABLE: {
		struct engkr_event *new_ring = NULL;

		mutex_lock(&engkr_ctrl_mutex);
		if (!engkr_ring) {
			new_ring = vzalloc(ENGKR_RING_SIZE_BYTES);
			if (!new_ring) {
				mutex_unlock(&engkr_ctrl_mutex);
				*ret = -ENOMEM;
				return true;
			}
			spin_lock_irqsave(&engkr_ring_lock, flags);
			engkr_ring = new_ring;
			engkr_ring_head = 0;
			engkr_ring_tail = 0;
			engkr_ring_count = 0;
			engkr_total_events = 0;
			engkr_dropped_events = 0;
			spin_unlock_irqrestore(&engkr_ring_lock, flags);
		} else if (arg3) {
			spin_lock_irqsave(&engkr_ring_lock, flags);
			engkr_ring_head = 0;
			engkr_ring_tail = 0;
			engkr_ring_count = 0;
			engkr_total_events = 0;
			engkr_dropped_events = 0;
			spin_unlock_irqrestore(&engkr_ring_lock, flags);
		}
		atomic_set(&engkr_tracer_active, 1);
		mutex_unlock(&engkr_ctrl_mutex);
		*ret = 0;
		return true;
	}

	case ENGKR_CMD_DISABLE:
		atomic_set(&engkr_tracer_active, 0);
		*ret = 0;
		return true;

	case ENGKR_CMD_RESET:
		spin_lock_irqsave(&engkr_ring_lock, flags);
		engkr_ring_head = 0;
		engkr_ring_tail = 0;
		engkr_ring_count = 0;
		engkr_total_events = 0;
		engkr_dropped_events = 0;
		spin_unlock_irqrestore(&engkr_ring_lock, flags);
		*ret = 0;
		return true;

	case ENGKR_CMD_SET_PKG: {
		char *kpkg;
		long n;

		kpkg = kzalloc(ENGKR_PKG_MAX, GFP_KERNEL);
		if (!kpkg) {
			*ret = -ENOMEM;
			return true;
		}
		if (arg3) {
			n = strncpy_from_user(kpkg, (const char __user *)arg3,
					      ENGKR_PKG_MAX - 1);
			if (n < 0) {
				kfree(kpkg);
				*ret = -EFAULT;
				return true;
			}
		}
		spin_lock_irqsave(&engkr_ring_lock, flags);
		strlcpy(engkr_target_pkg, kpkg, sizeof(engkr_target_pkg));
		spin_unlock_irqrestore(&engkr_ring_lock, flags);
		kfree(kpkg);
		*ret = 0;
		return true;
	}

	case ENGKR_CMD_ADD_UID:
		engkr_add_uid_internal((u32)arg3);
		*ret = 0;
		return true;

	case ENGKR_CMD_CLEAR_UIDS:
		spin_lock_irqsave(&engkr_ring_lock, flags);
		memset(engkr_target_uids, 0, sizeof(engkr_target_uids));
		engkr_uid_count = 0;
		memset(engkr_target_pkg, 0, sizeof(engkr_target_pkg));
		spin_unlock_irqrestore(&engkr_ring_lock, flags);
		*ret = 0;
		return true;

	case ENGKR_CMD_MARKER: {
		struct engkr_event *ev;
		char *ktag;
		long n;

		ev = kmalloc(sizeof(*ev), GFP_KERNEL);
		ktag = kzalloc(ENGKR_MARKER_MAX, GFP_KERNEL);
		if (!ev || !ktag) {
			kfree(ev);
			kfree(ktag);
			*ret = -ENOMEM;
			return true;
		}
		if (arg3) {
			n = strncpy_from_user(ktag, (const char __user *)arg3,
					      ENGKR_MARKER_MAX - 1);
			if (n < 0) {
				kfree(ev);
				kfree(ktag);
				*ret = -EFAULT;
				return true;
			}
		}
		engkr_init_event(ev, EVT_MARKER, 0, 0, 0);
		strlcpy(ev->path, ktag, sizeof(ev->path));
		engkr_ring_push(ev);
		kfree(ev);
		kfree(ktag);
		*ret = 0;
		return true;
	}

	case ENGKR_CMD_READ_RING:
		*ret = engkr_cmd_read_ring((void __user *)arg3, arg4);
		return true;

	case ENGKR_CMD_GET_STATS: {
		struct engkr_stats *st;

		if (!arg3) {
			*ret = -EINVAL;
			return true;
		}
		st = kzalloc(sizeof(*st), GFP_KERNEL);
		if (!st) {
			*ret = -ENOMEM;
			return true;
		}
		spin_lock_irqsave(&engkr_ring_lock, flags);
		st->active = (u32)atomic_read(&engkr_tracer_active);
		st->uid_count = engkr_uid_count;
		memcpy(st->uids, engkr_target_uids, sizeof(st->uids));
		st->total_events = engkr_total_events;
		st->dropped_events = engkr_dropped_events;
		st->ring_used_bytes = (u64)engkr_ring_count * sizeof(struct engkr_event);
		st->ring_size_bytes = engkr_ring ? ENGKR_RING_SIZE_BYTES : 0;
		strlcpy(st->target_pkg, engkr_target_pkg, sizeof(st->target_pkg));
		spin_unlock_irqrestore(&engkr_ring_lock, flags);

		if (copy_to_user((void __user *)arg3, st, sizeof(*st)))
			*ret = -EFAULT;
		else
			*ret = 0;
		kfree(st);
		return true;
	}

	default:
		*ret = -EINVAL;
		return true;
	}
}
EXPORT_SYMBOL(engkr_handle_prctl);

/* ==================== Phase 2: Auto-UID Lock & VFS Hooks ==================== */

void __engkr_trace_chown(const struct path *path, uid_t user, int error)
{
	char *pbuf;
	char *fullpath;
	struct engkr_event *ev;

	if (error || user == (uid_t)-1 || user < 10000 || !engkr_has_target_pkg())
		return;

	pbuf = kmalloc(ENGKR_PATH_BUF_SZ, GFP_KERNEL);
	if (!pbuf)
		return;

	fullpath = engkr_resolve_path(path, pbuf, ENGKR_PATH_BUF_SZ);
	if (fullpath && engkr_path_matches(fullpath)) {
		if (engkr_add_uid_internal((u32)user)) {
			ev = kmalloc(sizeof(*ev), GFP_KERNEL);
			if (ev) {
				engkr_init_event(ev, EVT_AUTO_UID_LOCK, 0,
						 0, (s32)user);
				strlcpy(ev->path, fullpath, sizeof(ev->path));
				engkr_ring_push(ev);
				kfree(ev);
			}
		}
	}
	kfree(pbuf);
}

void __engkr_trace_open_ok(struct file *f, int flags, int fd)
{
	bool uid_hit;
	bool has_pkg;
	char *pbuf;
	char *fullpath;
	struct engkr_event *ev;

	if (!f)
		return;

	uid_hit = engkr_uid_matches(current_uid().val);
	has_pkg = engkr_has_target_pkg();
	if (!uid_hit && !has_pkg)
		return;

	pbuf = kmalloc(ENGKR_PATH_BUF_SZ, GFP_KERNEL);
	if (!pbuf)
		return;

	fullpath = engkr_resolve_path(&f->f_path, pbuf, ENGKR_PATH_BUF_SZ);
	if (!fullpath) {
		kfree(pbuf);
		return;
	}

	if (!uid_hit && !engkr_path_matches(fullpath)) {
		kfree(pbuf);
		return;
	}

	ev = kmalloc(sizeof(*ev), GFP_KERNEL);
	if (ev) {
		engkr_init_event(ev, EVT_OPEN, (u16)(flags & 0xFFFF), fd, flags);
		strlcpy(ev->path, fullpath, sizeof(ev->path));
		engkr_ring_push(ev);
		kfree(ev);
	}
	kfree(pbuf);
}

void __engkr_trace_open_err(const char *name, int flags, int err)
{
	bool uid_hit;
	struct engkr_event *ev;

	if (!name)
		return;

	uid_hit = engkr_uid_matches(current_uid().val);
	if (!uid_hit && !engkr_path_matches(name))
		return;

	ev = kmalloc(sizeof(*ev), GFP_KERNEL);
	if (ev) {
		engkr_init_event(ev, EVT_OPEN, (u16)(flags & 0xFFFF), err, flags);
		strlcpy(ev->path, name, sizeof(ev->path));
		engkr_ring_push(ev);
		kfree(ev);
	}
}

void __engkr_trace_faccessat(const char __user *filename, int mode, int res)
{
	bool uid_hit;
	bool has_pkg;
	char *kpath;
	long n;
	struct engkr_event *ev;

	if (!filename)
		return;

	uid_hit = engkr_uid_matches(current_uid().val);
	has_pkg = engkr_has_target_pkg();
	if (!uid_hit && !has_pkg)
		return;

	kpath = kmalloc(ENGKR_PATH_MAX, GFP_KERNEL);
	if (!kpath)
		return;

	n = strncpy_from_user(kpath, filename, ENGKR_PATH_MAX - 1);
	if (n <= 0) {
		kfree(kpath);
		return;
	}
	kpath[n] = '\0';

	if (!uid_hit && !engkr_path_matches(kpath)) {
		kfree(kpath);
		return;
	}

	ev = kmalloc(sizeof(*ev), GFP_KERNEL);
	if (ev) {
		engkr_init_event(ev, EVT_FACCESSAT, (u16)(mode & 0xFFFF),
				 res, mode);
		strlcpy(ev->path, kpath, sizeof(ev->path));
		engkr_ring_push(ev);
		kfree(ev);
	}
	kfree(kpath);
}

void __engkr_trace_stat(const char __user *filename, int flag, int error)
{
	char *kpath;
	long n;
	struct engkr_event *ev;

	if (!filename || !engkr_uid_matches(current_uid().val))
		return;

	kpath = kmalloc(ENGKR_PATH_MAX, GFP_KERNEL);
	if (!kpath)
		return;

	n = strncpy_from_user(kpath, filename, ENGKR_PATH_MAX - 1);
	if (n <= 0) {
		kfree(kpath);
		return;
	}
	kpath[n] = '\0';

	ev = kmalloc(sizeof(*ev), GFP_KERNEL);
	if (ev) {
		engkr_init_event(ev, EVT_STAT, (u16)(flag & 0xFFFF),
				 error, flag);
		strlcpy(ev->path, kpath, sizeof(ev->path));
		engkr_ring_push(ev);
		kfree(ev);
	}
	kfree(kpath);
}

void __engkr_trace_statfs(struct path *path)
{
	char *pbuf;
	char *fullpath;
	struct engkr_event *ev;

	if (!engkr_uid_matches(current_uid().val))
		return;

	pbuf = kmalloc(ENGKR_PATH_BUF_SZ, GFP_KERNEL);
	if (!pbuf)
		return;

	fullpath = engkr_resolve_path(path, pbuf, ENGKR_PATH_BUF_SZ);
	if (fullpath) {
		ev = kmalloc(sizeof(*ev), GFP_KERNEL);
		if (ev) {
			engkr_init_event(ev, EVT_STATFS, 0, 0, 0);
			strlcpy(ev->path, fullpath, sizeof(ev->path));
			engkr_ring_push(ev);
			kfree(ev);
		}
	}
	kfree(pbuf);
}

void __engkr_trace_readlink(struct path *path, int ret)
{
	char *pbuf;
	char *fullpath;
	struct engkr_event *ev;

	if (!engkr_uid_matches(current_uid().val))
		return;

	pbuf = kmalloc(ENGKR_PATH_BUF_SZ, GFP_KERNEL);
	if (!pbuf)
		return;

	fullpath = engkr_resolve_path(path, pbuf, ENGKR_PATH_BUF_SZ);
	if (fullpath) {
		ev = kmalloc(sizeof(*ev), GFP_KERNEL);
		if (ev) {
			engkr_init_event(ev, EVT_READLINK, 0, ret, 0);
			strlcpy(ev->path, fullpath, sizeof(ev->path));
			engkr_ring_push(ev);
			kfree(ev);
		}
	}
	kfree(pbuf);
}

void __engkr_trace_readdir(struct file *file)
{
	char *pbuf;
	char *fullpath;
	struct engkr_event *ev;

	if (!file || file->f_pos != 0)
		return;
	if (!engkr_uid_matches(current_uid().val))
		return;

	pbuf = kmalloc(ENGKR_PATH_BUF_SZ, GFP_KERNEL);
	if (!pbuf)
		return;

	fullpath = engkr_resolve_path(&file->f_path, pbuf, ENGKR_PATH_BUF_SZ);
	if (fullpath) {
		ev = kmalloc(sizeof(*ev), GFP_KERNEL);
		if (ev) {
			engkr_init_event(ev, EVT_READDIR, 0, 0, 0);
			strlcpy(ev->path, fullpath, sizeof(ev->path));
			engkr_ring_push(ev);
			kfree(ev);
		}
	}
	kfree(pbuf);
}

void __engkr_trace_unlink(const char *name, int error)
{
	bool uid_hit;
	struct engkr_event *ev;

	if (!name)
		return;

	uid_hit = engkr_uid_matches(current_uid().val);
	if (!uid_hit && !engkr_path_matches(name))
		return;

	ev = kmalloc(sizeof(*ev), GFP_KERNEL);
	if (ev) {
		engkr_init_event(ev, EVT_UNLINK, 0, error, 0);
		strlcpy(ev->path, name, sizeof(ev->path));
		engkr_ring_push(ev);
		kfree(ev);
	}
}

void __engkr_trace_rename(const char *oldname, const char *newname, int error)
{
	bool uid_hit;
	struct engkr_event *ev;

	if (!oldname || !newname)
		return;

	uid_hit = engkr_uid_matches(current_uid().val);
	if (!uid_hit && !engkr_path_matches(oldname) &&
	    !engkr_path_matches(newname))
		return;

	ev = kmalloc(sizeof(*ev), GFP_KERNEL);
	if (ev) {
		engkr_init_event(ev, EVT_RENAME, 0, error, 0);
		strlcpy(ev->path, oldname, sizeof(ev->path));
		strlcpy(ev->extra, newname, sizeof(ev->extra));
		engkr_ring_push(ev);
		kfree(ev);
	}
}

void __engkr_trace_mkdir(struct path *parent, struct dentry *dentry,
			 umode_t mode, int error)
{
	bool uid_hit;
	bool has_pkg;
	char *pbuf;
	char *ppath;
	struct engkr_event *ev;

	if (!parent || !dentry)
		return;

	uid_hit = engkr_uid_matches(current_uid().val);
	has_pkg = engkr_has_target_pkg();
	if (!uid_hit && !has_pkg)
		return;

	pbuf = kmalloc(ENGKR_PATH_BUF_SZ, GFP_KERNEL);
	if (!pbuf)
		return;

	ppath = engkr_resolve_path(parent, pbuf, ENGKR_PATH_BUF_SZ);
	if (!ppath) {
		kfree(pbuf);
		return;
	}

	ev = kmalloc(sizeof(*ev), GFP_KERNEL);
	if (ev) {
		engkr_init_event(ev, EVT_MKDIR, (u16)(mode & 0xFFFF),
				 error, (s32)mode);
		snprintf(ev->path, sizeof(ev->path), "%s/%s",
			 ppath, dentry->d_name.name);
		if (uid_hit || engkr_path_matches(ev->path))
			engkr_ring_push(ev);
		kfree(ev);
	}
	kfree(pbuf);
}

void __engkr_trace_xattr(bool is_set, struct dentry *d, const char *kname,
			 const void *kvalue, ssize_t res)
{
	char *pbuf;
	char *dpath;
	struct engkr_event *ev;
	int pos;
	ssize_t i, lim;
	const unsigned char *bytes;

	if (!d || !kname || !engkr_uid_matches(current_uid().val))
		return;

	pbuf = kmalloc(ENGKR_PATH_BUF_SZ, GFP_KERNEL);
	if (!pbuf)
		return;

	dpath = dentry_path_raw(d, pbuf, ENGKR_PATH_BUF_SZ);
	ev = kmalloc(sizeof(*ev), GFP_KERNEL);
	if (ev) {
		engkr_init_event(ev, is_set ? EVT_SETXATTR : EVT_GETXATTR,
				 0, (s32)res, 0);
		if (!IS_ERR(dpath))
			strlcpy(ev->path, dpath, sizeof(ev->path));
		pos = scnprintf(ev->extra, sizeof(ev->extra), "%s", kname);
		if (kvalue && res > 0 && pos < (int)sizeof(ev->extra) - 2) {
			ev->extra[pos++] = '=';
			bytes = (const unsigned char *)kvalue;
			lim = (res < (ssize_t)(sizeof(ev->extra) - pos - 1)) ?
			      res : (ssize_t)(sizeof(ev->extra) - pos - 1);
			for (i = 0; i < lim; i++) {
				unsigned char c = bytes[i];

				ev->extra[pos++] = engkr_is_printable(c) ?
						   (char)c : '.';
			}
			ev->extra[pos] = '\0';
		}
		engkr_ring_push(ev);
		kfree(ev);
	}
	kfree(pbuf);
}

void __engkr_trace_mmap(struct file *file, unsigned long len,
			unsigned long prot, unsigned long flags)
{
	char *pbuf;
	char *fullpath;
	struct engkr_event *ev;

	if (!file || !engkr_uid_matches(current_uid().val))
		return;

	pbuf = kmalloc(ENGKR_PATH_BUF_SZ, GFP_KERNEL);
	if (!pbuf)
		return;

	fullpath = engkr_resolve_path(&file->f_path, pbuf, ENGKR_PATH_BUF_SZ);
	if (fullpath) {
		ev = kmalloc(sizeof(*ev), GFP_KERNEL);
		if (ev) {
			engkr_init_event(ev, EVT_MMAP, (u16)(flags & 0xFFFF),
					 (s32)(len & 0x7FFFFFFF), (s32)prot);
			strlcpy(ev->path, fullpath, sizeof(ev->path));
			engkr_ring_push(ev);
			kfree(ev);
		}
	}
	kfree(pbuf);
}

void __engkr_trace_execve(const char *filename, const char *argv_str)
{
	struct engkr_event *ev;

	if (!filename || !engkr_uid_matches(current_uid().val))
		return;

	ev = kmalloc(sizeof(*ev), GFP_KERNEL);
	if (ev) {
		engkr_init_event(ev, EVT_EXECVE, 0, 0, 0);
		strlcpy(ev->path, filename, sizeof(ev->path));
		if (argv_str && argv_str[0])
			strlcpy(ev->extra, argv_str, sizeof(ev->extra));
		engkr_ring_push(ev);
		kfree(ev);
	}
}

void __engkr_trace_uname(void)
{
	struct engkr_event *ev;

	if (!engkr_uid_matches(current_uid().val))
		return;

	ev = kmalloc(sizeof(*ev), GFP_KERNEL);
	if (ev) {
		engkr_init_event(ev, EVT_UNAME, 0, 0, 0);
		engkr_ring_push(ev);
		kfree(ev);
	}
}

void __engkr_trace_ptrace(long request, long pid)
{
	struct engkr_event *ev;

	if (!engkr_uid_matches(current_uid().val))
		return;

	ev = kmalloc(sizeof(*ev), GFP_KERNEL);
	if (ev) {
		engkr_init_event(ev, EVT_PTRACE, 0, 0, (s32)request);
		snprintf(ev->extra, sizeof(ev->extra), "pid=%ld", pid);
		engkr_ring_push(ev);
		kfree(ev);
	}
}

/* ==================== Phase 3: Binder, IOCTL, Netlink, Sockets ==================== */

void __engkr_trace_binder(int reply, struct task_struct *peer_tsk, u32 code,
			  u32 bflags, const void __user *ubuf,
			  size_t data_size)
{
	struct engkr_event *ev;
	unsigned char *kbuf = NULL;
	char peer_comm[TASK_COMM_LEN];
	size_t copy_len = 0;

	if (!reply) {
		if (!engkr_uid_matches(current_uid().val))
			return;
	} else {
		if (!peer_tsk || !engkr_uid_matches(task_uid(peer_tsk).val))
			return;
	}

	ev = kmalloc(sizeof(*ev), GFP_KERNEL);
	if (!ev)
		return;

	if (ubuf && data_size > 0) {
		copy_len = (data_size > ENGKR_BINDER_CAPTURE_SZ) ?
			   ENGKR_BINDER_CAPTURE_SZ : data_size;
		kbuf = kmalloc(copy_len, GFP_KERNEL);
		if (kbuf) {
			if (copy_from_user(kbuf, ubuf, copy_len)) {
				kfree(kbuf);
				kbuf = NULL;
				copy_len = 0;
			}
		} else {
			copy_len = 0;
		}
	}

	engkr_init_event(ev, reply ? EVT_BINDER_REPLY : EVT_BINDER_TX,
			 (u16)(bflags & 0xFFFF), (s32)data_size, (s32)code);

	if (peer_tsk) {
		get_task_comm(peer_comm, peer_tsk);
		snprintf(ev->path, sizeof(ev->path), "peer=%s pid=%d uid=%u",
			 peer_comm, peer_tsk->tgid, task_uid(peer_tsk).val);
	} else {
		strlcpy(ev->path, "peer=unknown", sizeof(ev->path));
	}

	engkr_parse_binder_parcel(ev->extra, sizeof(ev->extra),
				  kbuf, copy_len, data_size);

	engkr_ring_push(ev);
	kfree(kbuf);
	kfree(ev);
}
EXPORT_SYMBOL(__engkr_trace_binder);

static bool engkr_ioctl_is_spam(const char *path)
{
	if (!path)
		return false;
	if (strcmp(path, "/dev/binder") == 0 ||
	    strcmp(path, "/dev/hwbinder") == 0 ||
	    strcmp(path, "/dev/vndbinder") == 0 ||
	    strcmp(path, "/dev/kgsl-3d0") == 0 ||
	    strncmp(path, "/dev/ashmem", 11) == 0)
		return true;
	return false;
}

void __engkr_trace_ioctl(struct file *filp, unsigned int cmd,
			 unsigned long arg, bool is_compat)
{
	char *pbuf;
	char *fullpath;
	struct engkr_event *ev;

	if (!filp || !engkr_uid_matches(current_uid().val))
		return;

	pbuf = kmalloc(ENGKR_PATH_BUF_SZ, GFP_KERNEL);
	if (!pbuf)
		return;

	fullpath = engkr_resolve_path(&filp->f_path, pbuf, ENGKR_PATH_BUF_SZ);
	if (fullpath && engkr_ioctl_is_spam(fullpath)) {
		kfree(pbuf);
		return;
	}

	ev = kmalloc(sizeof(*ev), GFP_KERNEL);
	if (ev) {
		engkr_init_event(ev, EVT_IOCTL, is_compat ? 1 : 0, 0, (s32)cmd);
		if (fullpath)
			strlcpy(ev->path, fullpath, sizeof(ev->path));
		else
			strlcpy(ev->path, "(unknown)", sizeof(ev->path));
		snprintf(ev->extra, sizeof(ev->extra), "cmd=0x%08x arg=0x%lx",
			 cmd, arg);
		engkr_ring_push(ev);
		kfree(ev);
	}
	kfree(pbuf);
}
EXPORT_SYMBOL(__engkr_trace_ioctl);

void __engkr_trace_netlink(int protocol, u16 nlmsg_type, u16 nlmsg_flags,
			   size_t len)
{
	struct engkr_event *ev;

	if (!engkr_uid_matches(current_uid().val))
		return;

	ev = kmalloc(sizeof(*ev), GFP_KERNEL);
	if (ev) {
		engkr_init_event(ev, EVT_NETLINK, nlmsg_type,
				 (s32)len, (s32)protocol);
		snprintf(ev->path, sizeof(ev->path), "proto=%d type=%u",
			 protocol, (unsigned int)nlmsg_type);
		snprintf(ev->extra, sizeof(ev->extra), "nlmsg_flags=0x%04x",
			 (unsigned int)nlmsg_flags);
		engkr_ring_push(ev);
		kfree(ev);
	}
}
EXPORT_SYMBOL(__engkr_trace_netlink);

void __engkr_trace_tcp_connect(const struct sockaddr *uaddr, int addr_len)
{
	struct engkr_event *ev;

	if (!uaddr || addr_len < (int)sizeof(uaddr->sa_family))
		return;
	if (!engkr_uid_matches(current_uid().val))
		return;

	ev = kmalloc(sizeof(*ev), GFP_KERNEL);
	if (!ev)
		return;

	if (uaddr->sa_family == AF_INET &&
	    addr_len >= (int)sizeof(struct sockaddr_in)) {
		const struct sockaddr_in *sin =
			(const struct sockaddr_in *)uaddr;
		u16 port = ntohs(sin->sin_port);

		engkr_init_event(ev, EVT_TCP_CONNECT, AF_INET, 0, (s32)port);
		snprintf(ev->path, sizeof(ev->path), "ipv4:%pI4:%u",
			 &sin->sin_addr.s_addr, (unsigned int)port);
		engkr_ring_push(ev);
	} else if (uaddr->sa_family == AF_INET6 &&
		   addr_len >= (int)sizeof(struct sockaddr_in6)) {
		const struct sockaddr_in6 *sin6 =
			(const struct sockaddr_in6 *)uaddr;
		u16 port = ntohs(sin6->sin6_port);

		engkr_init_event(ev, EVT_TCP_CONNECT, AF_INET6, 0, (s32)port);
		snprintf(ev->path, sizeof(ev->path), "ipv6:[%pI6c]:%u",
			 &sin6->sin6_addr, (unsigned int)port);
		engkr_ring_push(ev);
	}

	kfree(ev);
}
EXPORT_SYMBOL(__engkr_trace_tcp_connect);

void __engkr_trace_udp4_send(__be32 daddr, __be16 dport, size_t len)
{
	struct engkr_event *ev;
	u16 port;

	if (!engkr_uid_matches(current_uid().val))
		return;

	ev = kmalloc(sizeof(*ev), GFP_KERNEL);
	if (!ev)
		return;

	port = ntohs(dport);
	engkr_init_event(ev, EVT_UDP_SEND, AF_INET, (s32)len, (s32)port);
	snprintf(ev->path, sizeof(ev->path), "udp4:%pI4:%u",
		 &daddr, (unsigned int)port);
	engkr_ring_push(ev);
	kfree(ev);
}
EXPORT_SYMBOL(__engkr_trace_udp4_send);

void __engkr_trace_udp6_send(const struct in6_addr *daddr, __be16 dport,
			     size_t len)
{
	struct engkr_event *ev;
	u16 port;

	if (!daddr || !engkr_uid_matches(current_uid().val))
		return;

	ev = kmalloc(sizeof(*ev), GFP_KERNEL);
	if (!ev)
		return;

	port = ntohs(dport);
	engkr_init_event(ev, EVT_UDP_SEND, AF_INET6, (s32)len, (s32)port);
	snprintf(ev->path, sizeof(ev->path), "udp6:[%pI6c]:%u",
		 daddr, (unsigned int)port);
	engkr_ring_push(ev);
	kfree(ev);
}
EXPORT_SYMBOL(__engkr_trace_udp6_send);

void __engkr_trace_unix_connect(const struct sockaddr *uaddr, int addr_len)
{
	const struct sockaddr_un *sunaddr;
	struct engkr_event *ev;
	int path_len;
	int i, pos;

	if (!uaddr || addr_len <= (int)offsetof(struct sockaddr_un, sun_path))
		return;
	if (!engkr_uid_matches(current_uid().val))
		return;

	sunaddr = (const struct sockaddr_un *)uaddr;
	path_len = addr_len - (int)offsetof(struct sockaddr_un, sun_path);
	if (path_len > (int)sizeof(sunaddr->sun_path))
		path_len = (int)sizeof(sunaddr->sun_path);

	ev = kmalloc(sizeof(*ev), GFP_KERNEL);
	if (!ev)
		return;

	engkr_init_event(ev, EVT_UNIX_CONNECT, AF_UNIX, 0, path_len);
	if (sunaddr->sun_path[0] == '\0') {
		/* Linux abstract namespace socket */
		pos = 0;
		ev->path[pos++] = '@';
		for (i = 1; i < path_len && pos < (int)sizeof(ev->path) - 1; i++) {
			unsigned char c = (unsigned char)sunaddr->sun_path[i];

			if (c == '\0')
				break;
			ev->path[pos++] = engkr_is_printable(c) ? (char)c : '.';
		}
		ev->path[pos] = '\0';
	} else {
		int copy_n = (path_len < (int)sizeof(ev->path) - 1) ?
			     path_len : (int)sizeof(ev->path) - 1;

		memcpy(ev->path, sunaddr->sun_path, copy_n);
		ev->path[copy_n] = '\0';
	}

	engkr_ring_push(ev);
	kfree(ev);
}
EXPORT_SYMBOL(__engkr_trace_unix_connect);
