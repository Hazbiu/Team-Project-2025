#!/bin/sh
mount -t devtmpfs devtmpfs /dev
roothash=$(cat /metadata/root.hash)
veritysetup create verity_root /dev/vda /dev/vda --root-hash="$roothash"
mount -o ro /dev/mapper/verity_root /newroot
exec switch_root /newroot /sbin/init
