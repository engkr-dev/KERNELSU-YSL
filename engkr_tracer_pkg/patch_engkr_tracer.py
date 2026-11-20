#!/usr/bin/env python3
"""
patch_engkr_tracer.py - Idempotent, fail-fast Phase 2 kernel injector for engkr_tracer
Target: Android Linux 4.9.262 (Xiaomi Redmi S2 / ysl) with KSU-Next + SUSFS + ZeroMount
"""

import argparse
import os
import shutil
import sys


def read_text(path):
    with open(path, "r", encoding="utf-8", errors="strict") as f:
        return f.read()


def write_text(path, content, dry_run):
    if dry_run:
        return
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)


def ensure_include(content, rel_path):
    inc = "#include <linux/engkr_tracer.h>"
    if inc in content:
        return content, False
    # Insert right after the first #include line
    lines = content.splitlines(keepends=True)
    for idx, line in enumerate(lines):
        if line.startswith("#include "):
            lines.insert(idx + 1, inc + "\n")
            return "".join(lines), True
    print(f"[-] FATAL: Could not find any #include line in {rel_path}")
    sys.exit(1)


def inject_exact(content, anchor, replacement, marker, rel_path, hook_name):
    if marker in content:
        print(f"[=] Already patched {rel_path} ({hook_name})")
        return content, False
    count = content.count(anchor)
    if count != 1:
        print(
            f"[-] FATAL: Anchor mismatch in {rel_path} ({hook_name}): "
            f"expected 1 match, found {count}"
        )
        sys.exit(1)
    new_content = content.replace(anchor, replacement, 1)
    print(f"[+] Patched {rel_path} ({hook_name})")
    return new_content, True


def patch_file(kernel_dir, rel_path, patches, dry_run, add_include=True):
    full_path = os.path.join(kernel_dir, rel_path)
    if not os.path.isfile(full_path):
        print(f"[-] FATAL: File not found: {full_path}")
        sys.exit(1)

    content = read_text(full_path)
    changed = False

    if add_include:
        content, inc_changed = ensure_include(content, rel_path)
        changed = changed or inc_changed

    for anchor, replacement, marker, hook_name in patches:
        content, did = inject_exact(
            content, anchor, replacement, marker, rel_path, hook_name
        )
        changed = changed or did

    if changed:
        write_text(full_path, content, dry_run)


def main():
    parser = argparse.ArgumentParser(description="Inject engkr_tracer Phase 2 hooks")
    parser.add_argument(
        "--kernel-dir",
        default=".",
        help="Path to kernel source root (default: current directory)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate all anchors without modifying any files",
    )
    args = parser.parse_args()

    kernel_dir = os.path.abspath(args.kernel_dir)
    pkg_dir = os.path.dirname(os.path.abspath(__file__))

    hdr_src = os.path.join(pkg_dir, "engkr_tracer.h")
    src_src = os.path.join(pkg_dir, "engkr_tracer.c")
    hdr_dst = os.path.join(kernel_dir, "include", "linux", "engkr_tracer.h")
    src_dst = os.path.join(kernel_dir, "drivers", "misc", "engkr_tracer.c")

    for p in (hdr_src, src_src):
        if not os.path.isfile(p):
            print(f"[-] FATAL: Missing package file: {p}")
            sys.exit(1)

    if args.dry_run:
        print(f"[*] DRY-RUN mode against kernel tree: {kernel_dir}")
        print(f"[+] Would copy engkr_tracer.h -> include/linux/engkr_tracer.h")
        print(f"[+] Would copy engkr_tracer.c -> drivers/misc/engkr_tracer.c")
    else:
        shutil.copy2(hdr_src, hdr_dst)
        shutil.copy2(src_src, src_dst)
        print(f"[+] Copied engkr_tracer.h -> include/linux/engkr_tracer.h")
        print(f"[+] Copied engkr_tracer.c -> drivers/misc/engkr_tracer.c")

    # 1. drivers/misc/Makefile
    mk_path = os.path.join(kernel_dir, "drivers", "misc", "Makefile")
    if not os.path.isfile(mk_path):
        print(f"[-] FATAL: Missing {mk_path}")
        sys.exit(1)
    mk_content = read_text(mk_path)
    if "engkr_tracer.o" in mk_content:
        print("[=] Already patched drivers/misc/Makefile (engkr_tracer.o)")
    else:
        if not mk_content.endswith("\n"):
            mk_content += "\n"
        mk_content += "obj-y\t\t\t\t+= engkr_tracer.o\n"
        write_text(mk_path, mk_content, args.dry_run)
        print("[+] Patched drivers/misc/Makefile (engkr_tracer.o)")

    # 2. kernel/sys.c (prctl + newuname)
    patch_file(
        kernel_dir,
        "kernel/sys.c",
        [
            (
                "\terror = security_task_prctl(option, arg2, arg3, arg4, arg5);\n",
                "\tif (engkr_handle_prctl(option, arg2, arg3, arg4, arg5, &error))\n"
                "\t\treturn error;\n\n"
                "\terror = security_task_prctl(option, arg2, arg3, arg4, arg5);\n",
                "engkr_handle_prctl(",
                "prctl",
            ),
            (
                "#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME\n"
                "\tsusfs_spoof_uname(&tmp);\n"
                "#endif\n"
                "\tup_read(&uts_sem);\n",
                "#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME\n"
                "\tsusfs_spoof_uname(&tmp);\n"
                "#endif\n"
                "\tup_read(&uts_sem);\n"
                "\tengkr_trace_uname();\n",
                "engkr_trace_uname(",
                "newuname",
            ),
        ],
        args.dry_run,
    )

    # 3. fs/open.c (do_sys_open ok/err, chown_common, faccessat)
    patch_file(
        kernel_dir,
        "fs/open.c",
        [
            (
                "\t\tif (IS_ERR(f)) {\n"
                "\t\t\tput_unused_fd(fd);\n"
                "\t\t\tfd = PTR_ERR(f);\n"
                "\t\t} else {\n"
                "\t\t\tfsnotify_open(f);\n"
                "\t\t\tfd_install(fd, f);\n"
                "\t\t}\n",
                "\t\tif (IS_ERR(f)) {\n"
                "\t\t\tput_unused_fd(fd);\n"
                "\t\t\tfd = PTR_ERR(f);\n"
                "\t\t\tengkr_trace_open_err(tmp->name, flags, fd);\n"
                "\t\t} else {\n"
                "\t\t\tengkr_trace_open_ok(f, flags, fd);\n"
                "\t\t\tfsnotify_open(f);\n"
                "\t\t\tfd_install(fd, f);\n"
                "\t\t}\n",
                "engkr_trace_open_ok(",
                "do_sys_open",
            ),
            (
                "\tif (delegated_inode) {\n"
                "\t\terror = break_deleg_wait(&delegated_inode);\n"
                "\t\tif (!error)\n"
                "\t\t\tgoto retry_deleg;\n"
                "\t}\n"
                "\treturn error;\n",
                "\tif (delegated_inode) {\n"
                "\t\terror = break_deleg_wait(&delegated_inode);\n"
                "\t\tif (!error)\n"
                "\t\t\tgoto retry_deleg;\n"
                "\t}\n"
                "\tengkr_trace_chown(path, user, error);\n"
                "\treturn error;\n",
                "engkr_trace_chown(",
                "chown_common",
            ),
            (
                "out:\n"
                "\trevert_creds(old_cred);\n"
                "\tput_cred(override_cred);\n"
                "\treturn res;\n",
                "out:\n"
                "\trevert_creds(old_cred);\n"
                "\tput_cred(override_cred);\n"
                "\tengkr_trace_faccessat(filename, mode, res);\n"
                "\treturn res;\n",
                "engkr_trace_faccessat(",
                "faccessat",
            ),
        ],
        args.dry_run,
    )

    # 4. fs/stat.c (vfs_fstatat + readlinkat)
    patch_file(
        kernel_dir,
        "fs/stat.c",
        [
            (
                "#ifdef CONFIG_ZEROMOUNT\n"
                "\tif (filename) {\n"
                "\t\tint zm_ret = zeromount_stat_hook(dfd, filename, stat, flag);\n"
                "\t\tif (zm_ret != -ENOENT)\n"
                "\t\t\treturn zm_ret;\n"
                "\t}\n"
                "#endif\n",
                "#ifdef CONFIG_ZEROMOUNT\n"
                "\tif (filename) {\n"
                "\t\tint zm_ret = zeromount_stat_hook(dfd, filename, stat, flag);\n"
                "\t\tif (zm_ret != -ENOENT) {\n"
                "\t\t\tengkr_trace_stat(filename, flag, zm_ret);\n"
                "\t\t\treturn zm_ret;\n"
                "\t\t}\n"
                "\t}\n"
                "#endif\n",
                "engkr_trace_stat(filename, flag, zm_ret)",
                "vfs_fstatat_zm",
            ),
            (
                "\terror = vfs_getattr(&path, stat);\n"
                "\tpath_put(&path);\n"
                "\tif (retry_estale(error, lookup_flags)) {\n"
                "\t\tlookup_flags |= LOOKUP_REVAL;\n"
                "\t\tgoto retry;\n"
                "\t}\n"
                "out:\n"
                "\treturn error;\n",
                "\terror = vfs_getattr(&path, stat);\n"
                "\tpath_put(&path);\n"
                "\tif (retry_estale(error, lookup_flags)) {\n"
                "\t\tlookup_flags |= LOOKUP_REVAL;\n"
                "\t\tgoto retry;\n"
                "\t}\n"
                "out:\n"
                "\tengkr_trace_stat(filename, flag, error);\n"
                "\treturn error;\n",
                "engkr_trace_stat(filename, flag, error)",
                "vfs_fstatat_out",
            ),
            (
                "\t\t\t\ttouch_atime(&path);\n"
                "\t\t\t\terror = vfs_readlink(path.dentry, buf, bufsiz);\n",
                "\t\t\t\ttouch_atime(&path);\n"
                "\t\t\t\terror = vfs_readlink(path.dentry, buf, bufsiz);\n"
                "\t\t\t\tengkr_trace_readlink(&path, error);\n",
                "engkr_trace_readlink(",
                "readlinkat",
            ),
        ],
        args.dry_run,
    )

    # 5. fs/statfs.c (vfs_statfs)
    patch_file(
        kernel_dir,
        "fs/statfs.c",
        [
            (
                "#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT\n"
                "\tstruct inode *inode = path->dentry->d_inode;\n"
                "\n"
                "\tif (SUSFS_IS_INODE_OPEN_REDIRECT(inode)) {\n",
                "#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT\n"
                "\tstruct inode *inode = path->dentry->d_inode;\n"
                "#endif // #ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT\n"
                "\tengkr_trace_statfs(path);\n"
                "#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT\n"
                "\tif (SUSFS_IS_INODE_OPEN_REDIRECT(inode)) {\n",
                "engkr_trace_statfs(",
                "vfs_statfs",
            ),
        ],
        args.dry_run,
    )

    # 6. fs/readdir.c (iterate_dir)
    patch_file(
        kernel_dir,
        "fs/readdir.c",
        [
            (
                "int iterate_dir(struct file *file, struct dir_context *ctx)\n"
                "{\n"
                "\tstruct inode *inode = file_inode(file);\n"
                "\tbool shared = false;\n"
                "\tint res = -ENOTDIR;\n",
                "int iterate_dir(struct file *file, struct dir_context *ctx)\n"
                "{\n"
                "\tstruct inode *inode = file_inode(file);\n"
                "\tbool shared = false;\n"
                "\tint res = -ENOTDIR;\n"
                "\tengkr_trace_readdir(file);\n",
                "engkr_trace_readdir(",
                "iterate_dir",
            ),
        ],
        args.dry_run,
    )

    # 7. fs/namei.c (mkdirat, do_unlinkat, renameat2)
    patch_file(
        kernel_dir,
        "fs/namei.c",
        [
            (
                "\terror = security_path_mkdir(&path, dentry, mode);\n"
                "\tif (!error)\n"
                "\t\terror = vfs_mkdir2(path.mnt, path.dentry->d_inode, dentry, mode);\n"
                "\tdone_path_create(&path, dentry);\n",
                "\terror = security_path_mkdir(&path, dentry, mode);\n"
                "\tif (!error)\n"
                "\t\terror = vfs_mkdir2(path.mnt, path.dentry->d_inode, dentry, mode);\n"
                "\tengkr_trace_mkdir(&path, dentry, mode, error);\n"
                "\tdone_path_create(&path, dentry);\n",
                "engkr_trace_mkdir(",
                "mkdirat",
            ),
            (
                "exit1:\n"
                "\tpath_put(&path);\n"
                "\tputname(name);\n"
                "\tif (retry_estale(error, lookup_flags)) {\n"
                "\t\tlookup_flags |= LOOKUP_REVAL;\n"
                "\t\tinode = NULL;\n"
                "\t\tgoto retry;\n"
                "\t}\n",
                "exit1:\n"
                "\tengkr_trace_unlink(name->name, error);\n"
                "\tpath_put(&path);\n"
                "\tputname(name);\n"
                "\tif (retry_estale(error, lookup_flags)) {\n"
                "\t\tlookup_flags |= LOOKUP_REVAL;\n"
                "\t\tinode = NULL;\n"
                "\t\tgoto retry;\n"
                "\t}\n",
                "engkr_trace_unlink(",
                "do_unlinkat",
            ),
            (
                "exit2:\n"
                "\tif (retry_estale(error, lookup_flags))\n"
                "\t\tshould_retry = true;\n"
                "\tpath_put(&new_path);\n"
                "\tputname(to);\n",
                "exit2:\n"
                "\tengkr_trace_rename(from->name, to->name, error);\n"
                "\tif (retry_estale(error, lookup_flags))\n"
                "\t\tshould_retry = true;\n"
                "\tpath_put(&new_path);\n"
                "\tputname(to);\n",
                "engkr_trace_rename(",
                "renameat2",
            ),
        ],
        args.dry_run,
    )

    # 8. fs/xattr.c (setxattr + getxattr)
    patch_file(
        kernel_dir,
        "fs/xattr.c",
        [
            (
                "\terror = vfs_setxattr(d, kname, kvalue, size, flags);\n",
                "\terror = vfs_setxattr(d, kname, kvalue, size, flags);\n"
                "\tengkr_trace_xattr(true, d, kname, kvalue, error ? error : (ssize_t)size);\n",
                "engkr_trace_xattr(true,",
                "setxattr",
            ),
            (
                "\terror = vfs_getxattr(d, kname, kvalue, size);\n",
                "\terror = vfs_getxattr(d, kname, kvalue, size);\n"
                "\tengkr_trace_xattr(false, d, kname, kvalue, error);\n",
                "engkr_trace_xattr(false,",
                "getxattr",
            ),
        ],
        args.dry_run,
    )

    # 9. mm/mmap.c (do_mmap)
    patch_file(
        kernel_dir,
        "mm/mmap.c",
        [
            (
                "\taddr = mmap_region(file, addr, len, vm_flags, pgoff);\n"
                "\tif (!IS_ERR_VALUE(addr) &&\n"
                "\t    ((vm_flags & VM_LOCKED) ||\n"
                "\t     (flags & (MAP_POPULATE | MAP_NONBLOCK)) == MAP_POPULATE))\n"
                "\t\t*populate = len;\n"
                "\treturn addr;\n",
                "\taddr = mmap_region(file, addr, len, vm_flags, pgoff);\n"
                "\tif (!IS_ERR_VALUE(addr)) {\n"
                "\t\tengkr_trace_mmap(file, len, prot, flags);\n"
                "\t\tif ((vm_flags & VM_LOCKED) ||\n"
                "\t\t    (flags & (MAP_POPULATE | MAP_NONBLOCK)) == MAP_POPULATE)\n"
                "\t\t\t*populate = len;\n"
                "\t}\n"
                "\treturn addr;\n",
                "engkr_trace_mmap(",
                "do_mmap",
            ),
        ],
        args.dry_run,
    )

    # 10. fs/exec.c (helper for struct user_arg_ptr + do_execveat_common)
    exec_helper = (
        "static noinline void engkr_execve_helper(const char *filename,\n"
        "\t\t\t\t\t struct user_arg_ptr argv)\n"
        "{\n"
        "\tchar *abuf;\n"
        "\tchar *tmp;\n"
        "\tint i, pos = 0;\n"
        "\n"
        "\tif (!engkr_tracer_is_active())\n"
        "\t\treturn;\n"
        "\tabuf = kzalloc(ENGKR_EXTRA_MAX, GFP_KERNEL);\n"
        "\ttmp = kmalloc(64, GFP_KERNEL);\n"
        "\tif (abuf && tmp) {\n"
        "\t\tfor (i = 0; i < 4 && pos < ENGKR_EXTRA_MAX - 2; i++) {\n"
        "\t\t\tconst char __user *p = get_user_arg_ptr(argv, i);\n"
        "\t\t\tlong n;\n"
        "\n"
        "\t\t\tif (!p || IS_ERR(p))\n"
        "\t\t\t\tbreak;\n"
        "\t\t\tn = strncpy_from_user(tmp, p, 63);\n"
        "\t\t\tif (n <= 0)\n"
        "\t\t\t\tbreak;\n"
        "\t\t\ttmp[n] = '\\0';\n"
        "\t\t\tpos += scnprintf(abuf + pos, ENGKR_EXTRA_MAX - pos,\n"
        "\t\t\t\t\t \"%s%s\", pos ? \" \" : \"\", tmp);\n"
        "\t\t}\n"
        "\t\tengkr_trace_execve(filename, abuf);\n"
        "\t}\n"
        "\tkfree(tmp);\n"
        "\tkfree(abuf);\n"
        "}\n\n"
    )
    patch_file(
        kernel_dir,
        "fs/exec.c",
        [
            (
                "static int do_execveat_common(int fd, struct filename *filename,\n",
                exec_helper + "static int do_execveat_common(int fd, struct filename *filename,\n",
                "engkr_execve_helper(",
                "execve_helper",
            ),
            (
                "\tif (IS_ERR(filename))\n"
                "\t\treturn PTR_ERR(filename);\n",
                "\tif (IS_ERR(filename))\n"
                "\t\treturn PTR_ERR(filename);\n"
                "\tengkr_execve_helper(filename->name, argv);\n",
                "engkr_execve_helper(filename->name, argv)",
                "do_execveat_common",
            ),
        ],
        args.dry_run,
    )

    # 11. kernel/ptrace.c (native + compat ptrace)
    patch_file(
        kernel_dir,
        "kernel/ptrace.c",
        [
            (
                "SYSCALL_DEFINE4(ptrace, long, request, long, pid, unsigned long, addr,\n"
                "\t\tunsigned long, data)\n"
                "{\n"
                "\tstruct task_struct *child;\n"
                "\tlong ret;\n",
                "SYSCALL_DEFINE4(ptrace, long, request, long, pid, unsigned long, addr,\n"
                "\t\tunsigned long, data)\n"
                "{\n"
                "\tstruct task_struct *child;\n"
                "\tlong ret;\n"
                "\n"
                "\tengkr_trace_ptrace(request, pid);\n",
                "\tengkr_trace_ptrace(request, pid);\n\n\tif (request == PTRACE_TRACEME) {\n\t\tret = ptrace_traceme();\n\t\tif (!ret)",
                "sys_ptrace",
            ),
            (
                "COMPAT_SYSCALL_DEFINE4(ptrace, compat_long_t, request, compat_long_t, pid,\n"
                "\t\t       compat_long_t, addr, compat_long_t, data)\n"
                "{\n"
                "\tstruct task_struct *child;\n"
                "\tlong ret;\n",
                "COMPAT_SYSCALL_DEFINE4(ptrace, compat_long_t, request, compat_long_t, pid,\n"
                "\t\t       compat_long_t, addr, compat_long_t, data)\n"
                "{\n"
                "\tstruct task_struct *child;\n"
                "\tlong ret;\n"
                "\n"
                "\tengkr_trace_ptrace((long)request, (long)pid);\n",
                "engkr_trace_ptrace((long)request, (long)pid)",
                "compat_sys_ptrace",
            ),
        ],
        args.dry_run,
    )

    mode = "DRY-RUN PASSED" if args.dry_run else "PATCHING COMPLETE"
    print(f"\n[OK] engkr_tracer Phase 2 {mode}: all anchors verified.")


if __name__ == "__main__":
    main()
