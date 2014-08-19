#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <gcrypt.h>
#include <stdbool.h>

#include "signing-common.h"

#define PROG_NAME "xosigcheck"

#define ERROR(FMT,ARG...) \
	fprintf(stderr, PROG_NAME ":%s:%d: ERROR: " FMT, __FUNCTION__, __LINE__, ##ARG);

#define DBG(FMT,ARG...) \
	fprintf(stderr, PROG_NAME ":%s:%d: " FMT, __FUNCTION__, __LINE__, ##ARG); \

void print_usage(const char *exe_name)
{
	printf("usage:  %s -f <file.img>\n", exe_name);
	exit(EXIT_FAILURE);
}

#define SIG_SIZE 256

#define DATA_SEXP_FORMAT "(data\n (flags pkcs1)\n (hash sha256 #%s#))\n"
#define SIG_VAL_SEXP_FORMAT "(sig-val (rsa (s #%s#)))\n"

int append_file(const char *path, const void *buffer, size_t buf_size)
{
	int fd;
	ssize_t write_size;

	if (!buffer || !buf_size)
		return -ENOMEM;

	fd = open(path, O_WRONLY | O_APPEND | O_CLOEXEC, 0644);
	if (fd == -1) {
		ERROR("Error opening '%s' for writing \n", path);
		return -errno;
	}

	write_size = write(fd, buffer, buf_size);
	if (write_size == -1) {
		ERROR("Error writing file '%s' : %d \n", path, errno);
		goto return_errno;
	}

	close(fd);
	return write_size;

	return_errno:
	close(fd);
	return -errno;
}

int appended_sig(const char *filename)
{
	int ret;
	char digest_ascii_hex[66] = { 0,};
	char keydata_str[256];
	char sig_sexp_str[2048] = {0,};
	gcry_sexp_t priv_key_sexp = NULL;
	gcry_sexp_t keydata = NULL;
	gcry_sexp_t sign_result = NULL;
	gcry_sexp_t token = NULL;
	const char *sig_str;

	size_t erroff;
	size_t len;

	ret = get_sha256(filename, 0, digest_ascii_hex);
	if (ret) {
		ERROR("calculating sha256\n")
		return -1;
	}
	DBG("sha256: %s\n", digest_ascii_hex);

	priv_key_sexp = load_sexp_from_file("rootfs-key.sexp");
	if (!priv_key_sexp) {
		ERROR("loading key\n");
		return -1;
	}

	snprintf(keydata_str, sizeof(keydata_str)-1, DATA_SEXP_FORMAT, digest_ascii_hex);
	DBG("keydata: %s\n", keydata_str);
	ret = gcry_sexp_sscan(&keydata, &erroff, keydata_str, strlen(keydata_str));
	if (ret) {
		ERROR("sexp not not valid at %zd : %s\n", erroff, keydata_str);
		ret = EXIT_FAILURE;
		goto free_mem;
	}


	ret = gcry_pk_testkey(priv_key_sexp);
	if (ret) {
		ERROR("private key not valid\n");
		ret = EXIT_FAILURE;
		goto free_mem;
	}

	ret = gcry_pk_sign(&sign_result, keydata, priv_key_sexp);
	if (ret) {
		ERROR("signing error %d %s\n",  ret, gcry_strerror(ret));
		ret = EXIT_FAILURE;
		goto free_mem;
	}

	len = gcry_sexp_sprint(sign_result, GCRYSEXP_FMT_ADVANCED, sig_sexp_str, sizeof(sig_sexp_str)-1);

	if (len < 0) {
		ERROR("sexp print \n");
		ret = EXIT_FAILURE;
		goto free_mem;
	}
	DBG("sig=%s\n", sig_sexp_str);

	token = gcry_sexp_find_token(sign_result, "s", 1);
	if (!token) {
		ERROR("s token not found \n");
		ret = EXIT_FAILURE;
		goto free_mem;
	}
	sig_str = gcry_sexp_nth_data (token, 1, &len);
	DBG("sig len=%zd \n",len);

	if (len != 256) {
		ERROR("invalid sig length \n");
		ret = EXIT_FAILURE;
		goto free_mem;
	}

	append_file(filename, sig_str, len);

	ret = 0;
	free_mem:

	if (keydata)
		gcry_sexp_release(keydata);

	if (token)
		gcry_sexp_release(token);

	if (sign_result)
		gcry_sexp_release(sign_result);

	if (priv_key_sexp)
		gcry_sexp_release(priv_key_sexp);

	return ret;
}

int main(int argc, char *argv[]) 
{
	int opt;
	const char * filename = NULL;

	if (argc < 2) {
		print_usage(argv[0]);
	}


	while ((opt = getopt(argc, argv, "f:t:")) != -1) {
		switch (opt) {
			case 'f':
				filename = optarg;
				break;
			case 't':

				break;
			default: /* '?' */
				print_usage(argv[0]);
		}
	}

// 	if (optind >= argc) {
// 		fprintf(stderr, "Expected argument after options\n");
// 		exit(EXIT_FAILURE);
// 	}

	if (!filename) {
		ERROR("-f  filename  required \n");
		print_usage(argv[0]);
	}
	appended_sig(filename);


	return EXIT_SUCCESS;
}