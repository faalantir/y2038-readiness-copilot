CC=gcc
CFLAGS=-Wall -Wextra -m32 -D_TIME_BITS=64 -D_FILE_OFFSET_BITS=64
# Positive control example: some Linux/glibc 32-bit builds use these feature macros for 64-bit time support.

all:
	$(CC) $(CFLAGS) legacy_device.c -o legacy_device
