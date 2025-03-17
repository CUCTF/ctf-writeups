# Run from within linux source, installs to /build
# Vaguely ripped from the Arch Linux PKGBUILD (https://gitlab.archlinux.org/archlinux/packaging/packages/linux/-/blob/main/PKGBUILD?ref_type=heads)
#!/bin/bash

if [ $# -eq 0 ]; then
    exit 1
else
    builddir="$1" 
fi

mkdir -p "$builddir"


echo "Installing build files..."
# install -Dt "$builddir" -m644 .config Makefile Module.symvers System.map \
# localversion.* version vmlinux tools/bpf/bpftool/vmlinux.h
install -Dt "$builddir" -m644 .config Makefile
install -Dt "$builddir/kernel" -m644 kernel/Makefile
install -Dt "$builddir/arch/x86" -m644 arch/x86/Makefile
cp -t "$builddir" -a scripts
ln -srt "$builddir" "$builddir/scripts/gdb/vmlinux-gdb.py"

# required when STACK_VALIDATION is enabled
install -Dt "$builddir/tools/objtool" tools/objtool/objtool

# required when DEBUG_INFO_BTF_MODULES is enabled
install -Dt "$builddir/tools/bpf/resolve_btfids" tools/bpf/resolve_btfids/resolve_btfids

echo "Installing headers..."
cp -t "$builddir" -a include
cp -t "$builddir/arch/x86" -a arch/x86/include
install -Dt "$builddir/arch/x86/kernel" -m644 arch/x86/kernel/asm-offsets.s

install -Dt "$builddir/drivers/md" -m644 drivers/md/*.h
install -Dt "$builddir/net/mac80211" -m644 net/mac80211/*.h

# https://bugs.archlinux.org/task/13146
install -Dt "$builddir/drivers/media/i2c" -m644 drivers/media/i2c/msp3400-driver.h

# https://bugs.archlinux.org/task/20402
install -Dt "$builddir/drivers/media/usb/dvb-usb" -m644 drivers/media/usb/dvb-usb/*.h
install -Dt "$builddir/drivers/media/dvb-frontends" -m644 drivers/media/dvb-frontends/*.h
install -Dt "$builddir/drivers/media/tuners" -m644 drivers/media/tuners/*.h

# https://bugs.archlinux.org/task/71392
install -Dt "$builddir/drivers/iio/common/hid-sensors" -m644 drivers/iio/common/hid-sensors/*.h

echo "Installing KConfig files..."
find . -name 'Kconfig*' -exec install -Dm644 {} "$builddir/{}" \;

remove_unneeded_architectures() {
    local build_dir="$1"
    echo "Removing unneeded architectures..."
    local arch
    for arch in "$build_dir"/arch/*/; do
        [[ $arch = */x86/ ]] && continue
        echo "Removing $(basename "$arch")"
        rm -r "$arch"
    done
}

# Call the function with the builddir
# remove_unneeded_architectures "$builddir"

echo "Removing documentation..."
rm -r "$builddir/Documentation"

echo "Removing broken symlinks..."
find -L "$builddir" -type l -printf 'Removing %P\n' -delete

echo "Removing loose objects..."
find "$builddir" -type f -name '*.o' -printf 'Removing %P\n' -delete

# echo "Stripping build tools..."
# local file
# while read -rd '' file; do
# case "$(file -Sib "$file")" in
#     application/x-sharedlib\;*)      # Libraries (.so)
#     strip -v $STRIP_SHARED "$file" ;;
#     application/x-archive\;*)        # Libraries (.a)
#     strip -v $STRIP_STATIC "$file" ;;
#     application/x-executable\;*)     # Binaries
#     strip -v $STRIP_BINARIES "$file" ;;
#     application/x-pie-executable\;*) # Relocatable binaries
#     strip -v $STRIP_SHARED "$file" ;;
# esac
# done < <(find "$builddir" -type f -perm -u+x ! -name vmlinux -print0)

# echo "Stripping vmlinux..."
# strip -v $STRIP_STATIC "$builddir/vmlinux"

# echo "Adding symlink..."
# mkdir -p "$pkgdir/usr/src"
# ln -sr "$builddir" "$pkgdir/usr/src/$pkgbase