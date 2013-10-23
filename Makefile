ARCH = $(shell uname -m | sed s,i[3456789]86,ia32,)
CC = gcc
EFI_INCLUDE = /usr/include/efi
WARNINGS = -Wall -Wsign-compare -Werror -Wno-unused-variable
CFLAGS = $(WARNINGS) -O0 -ggdb -std=gnu99 \
	-I$(EFI_INCLUDE) -I$(EFI_INCLUDE)/$(ARCH)
LDFLAGS = $(shell pkg-config --libs openssl)

all : verify

verify : verify.o pe.o crypto.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

verify.o : verify.c wincert.h pe.h crypto.h
pe.o : pe.c wincert.h PeImage.h pe.h
crypto.o : crypto.h

%.o : %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean :
	@rm -vf *.o verify

.PHONY : clean all
