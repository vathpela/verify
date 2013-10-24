ARCH = $(shell uname -m | sed s,i[3456789]86,ia32,)
CC = gcc
EFI_INCLUDE = /usr/include/efi
WARNINGS = -Wall -Wsign-compare -Werror -Wno-unused-variable
CFLAGS = $(WARNINGS) -O0 -ggdb -std=gnu99 \
	-I$(EFI_INCLUDE) -I$(EFI_INCLUDE)/$(ARCH) -ICryptlib \
	-DEFI_FUNCTION_WRAPPER -DGNU_EFI_USE_MS_ABI
LDFLAGS = $(shell pkg-config --libs openssl) -LCryptlib
SUBDIRS = Cryptlib

all : verify

verify : verify.o pe.o crypto.o \
		Cryptlib/libcryptlib.a
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

Cryptlib/libcryptlib.a:
	$(MAKE) -C Cryptlib

verify.o : verify.c wincert.h pe.h crypto.h
pe.o : pe.c wincert.h PeImage.h pe.h
crypto.o : crypto.h

%.o : %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean :
	@rm -vf *.o verify
	@$(MAKE) -C Cryptlib clean

.PHONY : clean all
