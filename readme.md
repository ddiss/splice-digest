## splice-digest

A fast and simple file hasher, backed by Linux `AF_ALG`.

## Build

```shell
gcc -o splice-digest splice-digest.c
```

## Run

```shell
./splice-digest <hash-algorith> <input-file>
```
Examples:
```shell
./splice-digest md5 /boot/vmlinuz
./splice-digest sha1 /boot/vmlinuz
./splice-digest sha256 /boot/vmlinuz
./splice-digest sha512 /boot/vmlinuz
# /proc/crypto contains a list of available algorithms for your kernel
```
