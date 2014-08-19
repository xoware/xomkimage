#define _GNU_SOURCE 
#define _BSD_SOURCE
 
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <termios.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <malloc.h>
#include <endian.h>
#include <string.h>
#include <gcrypt.h>

#include "xomkimage.h"


// generate key
// openssl genrsa -out  key.pem 2048


// create public key
// openssl rsa -in key.pem -pubout > key.pub

// create S expression
// pkcs1-conv --public-key-info key.pem | sexp-conv

/*
 * The format of the file downloaded is as follows:
 *
 *   GLOBAL HEADER
 *   IMAGE HEADER #1
 *   IMAGE HEADER #2
 *   ...
 *   IMAGE HEADER #n
 *   RAW DATA
 *
 *  where raw data is the concatenation of all images.
 */
#define PROG_NAME "xomkimage"

#define DBG(FMT,ARG...) \
	fprintf(stderr, PROG_NAME ":%s:%d: " FMT, __FUNCTION__, __LINE__, ##ARG); \

#define ERROR(FMT,ARG...) \
	fprintf(stderr, PROG_NAME ":%s:%d: ERROR: " FMT, __FUNCTION__, __LINE__, ##ARG); \
	

	static const char key_gen_params[] = "(genkey	(rsa(nbits 4:2048)))";

int main(int argc, char *argv[])
{
	gcry_sexp_t priv_key;
	gcry_sexp_t parms;
	size_t erroff;
	int ret;
	char buff[4096];

	ret = gcry_sexp_sscan(&parms, &erroff, key_gen_params, strlen(key_gen_params));
	if (ret) {
		ERROR("params not valid %d at %zd : %s\n", ret, erroff, key_gen_params);
		return EXIT_FAILURE;
	}

	ret = gcry_pk_genkey(&priv_key, parms);
	if (ret) {
		ERROR("Generating key\n");
	}

	ret = gcry_sexp_sprint(priv_key, GCRYSEXP_FMT_ADVANCED, buff, 4096);

	if (ret < 0) {
		ERROR("sexp print \n");
	} else {
		DBG("sig=%s\n\n", buff);
	}

	ret = gcry_pk_get_nbits(priv_key);
	DBG("nbits=%d\n", ret);

	ret = gcry_pk_testkey(priv_key);
	DBG("test key ret=%d == %s\n", ret, ret ? "FAIL" : "OK");


	exit(EXIT_SUCCESS);
}

/* EOF */
