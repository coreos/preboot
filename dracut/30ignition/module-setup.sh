#!/bin/bash
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh

depends() {
    echo qemu systemd url-lib network
}

install_ignition_unit() {
    local unit="$1"; shift
    local target="${1:-ignition-complete.target}"; shift
    local instantiated="${1:-$unit}"; shift
    inst_simple "$moddir/$unit" "$systemdsystemunitdir/$unit"
    mkdir -p "$initdir/$systemdsystemunitdir/$target.requires"
    ln_r "../$unit" "$systemdsystemunitdir/$target.requires/$instantiated"
}

install() {
    inst_multiple \
        basename \
        lsblk

    # Not all features of the configuration may be available on all systems
    # (e.g. on embedded systems), so only add applications which are actually
    # present
    inst_multiple -o \
        groupadd \
        groupdel \
        mkfs.btrfs \
        mkfs.ext4 \
        mkfs.vfat \
        mkfs.xfs \
        mkswap \
        sgdisk \
        useradd \
        userdel \
        usermod \
        wipefs

    # Needed for clevis binding; note all binaries related to unlocking are
    # included by the Clevis dracut modules.
    inst_multiple -o \
        clevis-encrypt-sss \
        clevis-encrypt-tang \
        clevis-encrypt-tpm2 \
        clevis-luks-bind \
        clevis-luks-common-functions \
        clevis-luks-unlock \
        pwmake \
        tpm2_create

    # Required by s390x's z/VM installation.
    # Supporting https://github.com/coreos/ignition/pull/865
    inst_multiple -o chccwdev vmur

    # Required on system using SELinux
    inst_multiple -o setfiles

    inst_script "$moddir/ignition-setup-base.sh" \
        "/usr/sbin/ignition-setup-base"
    inst_script "$moddir/ignition-setup-user.sh" \
        "/usr/sbin/ignition-setup-user"

    # Distro packaging is expected to install the ignition binary into the
    # module directory.
    inst_simple "$moddir/ignition" \
        "/usr/bin/ignition"

    # Rule to allow udev to discover unformatted encrypted devices
    inst_simple "$moddir/99-xx-ignition-systemd-cryptsetup.rules" \
        "/usr/lib/udev/rules.d/99-xx-ignition-systemd-cryptsetup.rules"

    # disable dictcheck
    inst_simple "$moddir/ignition-luks.conf" \
        "/etc/security/pwquality.conf.d/ignition-luks.conf"

    inst_simple "$moddir/ignition-generator" \
        "$systemdutildir/system-generators/ignition-generator"

    for x in "complete" "subsequent" "diskful" "diskful-subsequent"; do
        inst_simple "$moddir/ignition-$x.target" \
            "$systemdsystemunitdir/ignition-$x.target"
    done

    install_ignition_unit ignition-setup-base.service
    install_ignition_unit ignition-setup-user.service
    install_ignition_unit ignition-fetch.service
    install_ignition_unit ignition-fetch-offline.service
    install_ignition_unit ignition-disks.service
    install_ignition_unit ignition-mount.service
    install_ignition_unit ignition-files.service

    # units only started when we have a boot disk
    # path generated by systemd-escape --path /dev/disk/by-label/root
    install_ignition_unit ignition-remount-sysroot.service ignition-diskful.target

    # needed for openstack config drive support
    inst_rules 60-cdrom_id.rules
}
