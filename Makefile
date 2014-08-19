
CC ?= gcc

CFLAGS ?= -Wall -g -pipe

objs = md5.o

all: xomkimage_v1 xomkimage mk_key xosigcheck xosignappend

xomkimage: $(objs) xomkimage.c
	$(CC) $(CFLAGS) -o $@ $^

xomkimage_v1: xomkimage_v1.c signing-common.c
	$(CC) $(CFLAGS) -o $@ $^ -lgcrypt

mk_key: $(objs) mk_key.c
	$(CC) $(CFLAGS) -o $@ $^ -lgcrypt

xosigcheck:  xosigcheck.c
	$(CC) $(CFLAGS) -o $@ $^ -lgcrypt

xosignappend: xosignappend.c signing-common.c
	$(CC) $(CFLAGS) -o $@ $^ -lgcrypt

.c.o:
	$(CC) $(CFLAGS) -c $<

.PHONY: clean
clean:
	rm -f $(objs) xomkimage xosignappend xosigcheck mk_key xomkimage_v1
	
