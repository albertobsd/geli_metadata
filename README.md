# geli_metadata

Extract information about geom_eli in Full Disk Encryped Disks


compile:

cc -o eli_metadata eli_metadata.c -lmd


Usage

./eli_metadata sector.backup

Where sector.backup is the last 512 bytes of the device encryoted with geli.

# dd if=/dev/da1p1 of=./sector.backup bs=512 iseek=39845887 count=1
