
all : verify

verify : verify.o
	$(CC) $(CFLAGS) -o $@ $^

CFLAGS = -Wall -Werror -std=gnu99

%.o : %.c
	$(CC) $(CFLAGS) -c -o $@ $^

clean :
	@rm -vf *.o verify

.PHONY : clean
