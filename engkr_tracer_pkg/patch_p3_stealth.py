#!/usr/bin/env python3
"""
patch_p3_stealth.py - Idempotent, fail-fast Phase P3 Kernel Stealth Patcher
Target: Android Linux 4.9.262 (Xiaomi Redmi S2 / ysl) with KSU-Next + SUSFS v2.1.0
Scope:
  1. fs/statfs.c      : /data superblock STATFS f_fsid spoofing via engkr_spoof_statfs_fsid()
  2. include/linux/susfs.h : Fix KSTAT_SPOOF_CTIME_TV_SEC typo (1 < 8) -> (1 << 8)
  3. fs/susfs.c       : Auto-populate info.flags when 0, bind real inode->i_ino as target_ino,
                        hash by new_entry->target_ino, and verify entry->target_ino == target_ino
  4. net/core/neighbour.c : RTM_GETNEIGH NDA_LLADDR gateway MAC spoofing via engkr_spoof_neigh_lladdr()
"""

import argparse
import os
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


def patch_file(kernel_dir, rel_path, patches, dry_run, add_include=False):
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
    parser = argparse.ArgumentParser(
        description="Apply Phase P3 kernel stealth patches (STATFS f_fsid, SUS_KSTAT fixes, RTM_GETNEIGH)"
    )
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
    if args.dry_run:
        print(f"[*] DRY-RUN mode against kernel tree: {kernel_dir}")

    # 1. fs/statfs.c -> engkr_spoof_statfs_fsid() inside statfs_by_dentry()
    patch_file(
        kernel_dir,
        "fs/statfs.c",
        [
            (
                "\tretval = dentry->d_sb->s_op->statfs(dentry, buf);\n"
                "\tif (retval == 0 && buf->f_frsize == 0)\n"
                "\t\tbuf->f_frsize = buf->f_bsize;\n"
                "\treturn retval;\n",
                "\tretval = dentry->d_sb->s_op->statfs(dentry, buf);\n"
                "\tif (retval == 0) {\n"
                "\t\tif (buf->f_frsize == 0)\n"
                "\t\t\tbuf->f_frsize = buf->f_bsize;\n"
                "\t\tengkr_spoof_statfs_fsid(dentry, buf);\n"
                "\t}\n"
                "\treturn retval;\n",
                "engkr_spoof_statfs_fsid(",
                "statfs_by_dentry",
            ),
        ],
        args.dry_run,
        add_include=True,
    )

    # 2. include/linux/susfs.h -> fix KSTAT_SPOOF_CTIME_TV_SEC (1 < 8) -> (1 << 8)
    patch_file(
        kernel_dir,
        "include/linux/susfs.h",
        [
            (
                "#define KSTAT_SPOOF_MTIME_TV_SEC (1 << 6)\n"
                "#define KSTAT_SPOOF_MTIME_TV_NSEC (1 << 7)\n"
                "#define KSTAT_SPOOF_CTIME_TV_SEC (1 < 8)\n"
                "#define KSTAT_SPOOF_CTIME_TV_NSEC (1 << 9)\n",
                "#define KSTAT_SPOOF_MTIME_TV_SEC (1 << 6)\n"
                "#define KSTAT_SPOOF_MTIME_TV_NSEC (1 << 7)\n"
                "#define KSTAT_SPOOF_CTIME_TV_SEC (1 << 8)\n"
                "#define KSTAT_SPOOF_CTIME_TV_NSEC (1 << 9)\n",
                "#define KSTAT_SPOOF_CTIME_TV_SEC (1 << 8)",
                "KSTAT_SPOOF_CTIME_TV_SEC",
            ),
        ],
        args.dry_run,
        add_include=False,
    )

    # 3. fs/susfs.c -> sus_kstat target_ino, flags normalization, and hash collision guard
    patch_file(
        kernel_dir,
        "fs/susfs.c",
        [
            (
                "\t\tset_bit(AS_FLAGS_SUS_KSTAT, &fi->inode.i_state);\n"
                "\t\tnew_entry->is_fuse = true;\n"
                "\t\tnew_entry->target_dev = fi->inode.i_sb->s_dev;\n",
                "\t\tset_bit(AS_FLAGS_SUS_KSTAT, &fi->inode.i_state);\n"
                "\t\tnew_entry->is_fuse = true;\n"
                "\t\tnew_entry->target_ino = fi->inode.i_ino;\n"
                "\t\tnew_entry->info.target_ino = fi->inode.i_ino;\n"
                "\t\tnew_entry->target_dev = fi->inode.i_sb->s_dev;\n",
                "new_entry->target_ino = fi->inode.i_ino;",
                "susfs_mark_inode_sus_kstat_fuse",
            ),
            (
                "\tset_bit(AS_FLAGS_SUS_KSTAT, &inode->i_state);\n"
                "\tnew_entry->is_fuse = false;\n"
                "\tnew_entry->target_dev = inode->i_sb->s_dev;\n",
                "\tset_bit(AS_FLAGS_SUS_KSTAT, &inode->i_state);\n"
                "\tnew_entry->is_fuse = false;\n"
                "\tnew_entry->target_ino = inode->i_ino;\n"
                "\tnew_entry->info.target_ino = inode->i_ino;\n"
                "\tnew_entry->target_dev = inode->i_sb->s_dev;\n",
                "new_entry->target_ino = inode->i_ino;",
                "susfs_mark_inode_sus_kstat_reg",
            ),
            (
                "void susfs_add_sus_kstat(void __user **user_info) {\n"
                "\tstruct st_susfs_sus_kstat info = {0};\n"
                "\tstruct st_susfs_sus_kstat_hlist *new_entry, *tmp_entry;\n"
                "\tstruct hlist_node *tmp_hlist_node;\n"
                "\n"
                "\tif (copy_from_user(&info, (struct st_susfs_sus_kstat __user*)*user_info, sizeof(info))) {\n"
                "\t\tinfo.err = -EFAULT;\n"
                "\t\tgoto out_copy_to_user;\n"
                "\t}\n"
                "\n"
                "\tif (*info.target_pathname == '\\0') {\n"
                "\t\tinfo.err = -EINVAL;\n"
                "\t\tgoto out_copy_to_user;\n"
                "\t}\n",
                "void susfs_add_sus_kstat(void __user **user_info) {\n"
                "\tstruct st_susfs_sus_kstat info = {0};\n"
                "\tstruct st_susfs_sus_kstat_hlist *new_entry, *tmp_entry;\n"
                "\tstruct hlist_node *tmp_hlist_node;\n"
                "\tint bkt;\n"
                "\n"
                "\tif (copy_from_user(&info, (struct st_susfs_sus_kstat __user*)*user_info, sizeof(info))) {\n"
                "\t\tinfo.err = -EFAULT;\n"
                "\t\tgoto out_copy_to_user;\n"
                "\t}\n"
                "\n"
                "\tif (*info.target_pathname == '\\0') {\n"
                "\t\tinfo.err = -EINVAL;\n"
                "\t\tgoto out_copy_to_user;\n"
                "\t}\n"
                "\n"
                "\tif (info.flags == 0) {\n"
                "\t\tif (info.spoofed_ino)\n"
                "\t\t\tinfo.flags |= KSTAT_SPOOF_INO;\n"
                "\t\tif (info.spoofed_dev)\n"
                "\t\t\tinfo.flags |= KSTAT_SPOOF_DEV;\n"
                "\t\tif (info.spoofed_nlink)\n"
                "\t\t\tinfo.flags |= KSTAT_SPOOF_NLINK;\n"
                "\t\tif (info.spoofed_size)\n"
                "\t\t\tinfo.flags |= KSTAT_SPOOF_SIZE;\n"
                "\t\tif (info.spoofed_atime_tv_sec || info.spoofed_atime_tv_nsec)\n"
                "\t\t\tinfo.flags |= KSTAT_SPOOF_ATIME_TV_SEC | KSTAT_SPOOF_ATIME_TV_NSEC;\n"
                "\t\tif (info.spoofed_mtime_tv_sec || info.spoofed_mtime_tv_nsec)\n"
                "\t\t\tinfo.flags |= KSTAT_SPOOF_MTIME_TV_SEC | KSTAT_SPOOF_MTIME_TV_NSEC;\n"
                "\t\tif (info.spoofed_ctime_tv_sec || info.spoofed_ctime_tv_nsec)\n"
                "\t\t\tinfo.flags |= KSTAT_SPOOF_CTIME_TV_SEC | KSTAT_SPOOF_CTIME_TV_NSEC;\n"
                "\t\tif (info.spoofed_blksize)\n"
                "\t\t\tinfo.flags |= KSTAT_SPOOF_BLKSIZE;\n"
                "\t\tif (info.spoofed_blocks)\n"
                "\t\t\tinfo.flags |= KSTAT_SPOOF_BLOCKS;\n"
                "\t}\n",
                "if (info.flags == 0) {",
                "susfs_add_sus_kstat_flags",
            ),
            (
                "// statically or not, check for duplicated entry, and remove it first if so\n"
                "\tmutex_lock(&susfs_mutex_lock_sus_kstat);\n"
                "\thash_for_each_possible_safe(SUS_KSTAT_HLIST, tmp_entry, tmp_hlist_node, node, info.target_ino) {\n",
                "// statically or not, check for duplicated entry, and remove it first if so\n"
                "\tmutex_lock(&susfs_mutex_lock_sus_kstat);\n"
                "\thash_for_each_safe(SUS_KSTAT_HLIST, bkt, tmp_hlist_node, tmp_entry, node) {\n",
                "// statically or not, check for duplicated entry, and remove it first if so\n"
                "\tmutex_lock(&susfs_mutex_lock_sus_kstat);\n"
                "\thash_for_each_safe(SUS_KSTAT_HLIST, bkt, tmp_hlist_node, tmp_entry, node) {",
                "susfs_add_sus_kstat_dup_walk",
            ),
            (
                "#endif\n"
                "\t\t\thash_del_rcu(&tmp_entry->node);\n"
                "\t\t\thash_add_rcu(SUS_KSTAT_HLIST, &new_entry->node, info.target_ino);\n"
                "\t\t\tmutex_unlock(&susfs_mutex_lock_sus_kstat);\n"
                "\t\t\tsynchronize_rcu();\n"
                "\t\t\tkfree(tmp_entry);\n"
                "\t\t\tinfo.err = 0;\n"
                "\t\t\tgoto out_copy_to_user;\n"
                "\t\t}\n"
                "\t}\n",
                "#endif\n"
                "\t\t\thash_del_rcu(&tmp_entry->node);\n"
                "\t\t\thash_add_rcu(SUS_KSTAT_HLIST, &new_entry->node, new_entry->target_ino);\n"
                "\t\t\tmutex_unlock(&susfs_mutex_lock_sus_kstat);\n"
                "\t\t\tsynchronize_rcu();\n"
                "\t\t\tkfree(tmp_entry);\n"
                "\t\t\tinfo.err = 0;\n"
                "\t\t\tgoto out_copy_to_user;\n"
                "\t\t}\n"
                "\t}\n",
                "#endif\n\t\t\thash_del_rcu(&tmp_entry->node);\n\t\t\thash_add_rcu(SUS_KSTAT_HLIST, &new_entry->node, new_entry->target_ino);",
                "susfs_add_sus_kstat_dup_hash",
            ),
            (
                "#endif\n"
                "\thash_add_rcu(SUS_KSTAT_HLIST, &new_entry->node, info.target_ino);\n"
                "\tmutex_unlock(&susfs_mutex_lock_sus_kstat);\n"
                "\tinfo.err = 0;\n",
                "#endif\n"
                "\thash_add_rcu(SUS_KSTAT_HLIST, &new_entry->node, new_entry->target_ino);\n"
                "\tmutex_unlock(&susfs_mutex_lock_sus_kstat);\n"
                "\tinfo.err = 0;\n",
                "#endif\n\thash_add_rcu(SUS_KSTAT_HLIST, &new_entry->node, new_entry->target_ino);\n\tmutex_unlock",
                "susfs_add_sus_kstat_new_hash",
            ),
            (
                "\t\t\tSUSFS_LOGI(\"updating target_ino from '%lu' to '%lu' for pathname: '%s' in SUS_KSTAT_HLIST\\n\",\n"
                "\t\t\t\t\ttmp_entry->target_ino, new_entry->target_ino, new_entry->info.target_pathname);\n"
                "\t\t\thash_del_rcu(&tmp_entry->node);\n"
                "\t\t\thash_add_rcu(SUS_KSTAT_HLIST, &new_entry->node, info.target_ino);\n",
                "\t\t\tSUSFS_LOGI(\"updating target_ino from '%lu' to '%lu' for pathname: '%s' in SUS_KSTAT_HLIST\\n\",\n"
                "\t\t\t\t\ttmp_entry->target_ino, new_entry->target_ino, new_entry->info.target_pathname);\n"
                "\t\t\thash_del_rcu(&tmp_entry->node);\n"
                "\t\t\thash_add_rcu(SUS_KSTAT_HLIST, &new_entry->node, new_entry->target_ino);\n",
                "new_entry->info.target_pathname);\n\t\t\thash_del_rcu(&tmp_entry->node);\n\t\t\thash_add_rcu(SUS_KSTAT_HLIST, &new_entry->node, new_entry->target_ino);",
                "susfs_update_sus_kstat_hash",
            ),
            (
                "\thash_for_each_possible_rcu(SUS_KSTAT_HLIST, entry, node, target_ino) {\n"
                "\t\tif (entry->target_dev == target_dev &&\n"
                "\t\t\tentry->is_fuse == is_fuse)\n"
                "\t\t{\n"
                "\t\t\tSUSFS_LOGI(\"spoofing kstat for path: %s, target_ino: %lu, target_dev: %u\\n\",\n",
                "\thash_for_each_possible_rcu(SUS_KSTAT_HLIST, entry, node, target_ino) {\n"
                "\t\tif (entry->target_ino == target_ino &&\n"
                "\t\t\tentry->target_dev == target_dev &&\n"
                "\t\t\tentry->is_fuse == is_fuse)\n"
                "\t\t{\n"
                "\t\t\tSUSFS_LOGI(\"spoofing kstat for path: %s, target_ino: %lu, target_dev: %u\\n\",\n",
                "if (entry->target_ino == target_ino &&\n\t\t\tentry->target_dev == target_dev &&\n\t\t\tentry->is_fuse == is_fuse)\n\t\t{\n\t\t\tSUSFS_LOGI(\"spoofing kstat for path:",
                "susfs_generic_fillattr_spoofer_ino",
            ),
            (
                "\thash_for_each_possible_rcu(SUS_KSTAT_HLIST, entry, node, target_ino) {\n"
                "\t\tif (entry->target_dev == target_dev &&\n"
                "\t\t\tentry->is_fuse == is_fuse)\n"
                "\t\t{\n"
                "\t\t\tSUSFS_LOGI(\"spoofing kstat for target_ino: %lu, target_dev: %u\\n\", target_ino, target_dev);\n",
                "\thash_for_each_possible_rcu(SUS_KSTAT_HLIST, entry, node, target_ino) {\n"
                "\t\tif (entry->target_ino == target_ino &&\n"
                "\t\t\tentry->target_dev == target_dev &&\n"
                "\t\t\tentry->is_fuse == is_fuse)\n"
                "\t\t{\n"
                "\t\t\tSUSFS_LOGI(\"spoofing kstat for target_ino: %lu, target_dev: %u\\n\", target_ino, target_dev);\n",
                "if (entry->target_ino == target_ino &&\n\t\t\tentry->target_dev == target_dev &&\n\t\t\tentry->is_fuse == is_fuse)\n\t\t{\n\t\t\tSUSFS_LOGI(\"spoofing kstat for target_ino:",
                "susfs_show_map_vma_spoofer_ino",
            ),
        ],
        args.dry_run,
        add_include=False,
    )

    # 4. net/core/neighbour.c -> engkr_spoof_neigh_lladdr() inside neigh_fill_info()
    patch_file(
        kernel_dir,
        "net/core/neighbour.c",
        [
            (
                "\tif (neigh->nud_state & NUD_VALID) {\n"
                "\t\tchar haddr[MAX_ADDR_LEN];\n"
                "\n"
                "\t\tneigh_ha_snapshot(haddr, neigh, neigh->dev);\n"
                "\t\tif (nla_put(skb, NDA_LLADDR, neigh->dev->addr_len, haddr) < 0) {\n",
                "\tif (neigh->nud_state & NUD_VALID) {\n"
                "\t\tchar haddr[MAX_ADDR_LEN];\n"
                "\n"
                "\t\tneigh_ha_snapshot(haddr, neigh, neigh->dev);\n"
                "\t\tengkr_spoof_neigh_lladdr(skb, (u8 *)haddr, neigh->dev->addr_len);\n"
                "\t\tif (nla_put(skb, NDA_LLADDR, neigh->dev->addr_len, haddr) < 0) {\n",
                "engkr_spoof_neigh_lladdr(",
                "neigh_fill_info",
            ),
        ],
        args.dry_run,
        add_include=True,
    )

    mode = "DRY-RUN PASSED" if args.dry_run else "PATCHING COMPLETE"
    print(f"\n[OK] Phase P3 stealth kernel patch {mode}: all anchors verified.")


if __name__ == "__main__":
    main()
