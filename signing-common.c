#define _GNU_SOURCE 
#define _BSD_SOURCE
 
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>
#include <libgen.h>
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

#define DBG(FMT,ARG...) \
fprintf(stderr, ":%s:%d: " FMT, __FUNCTION__, __LINE__, ##ARG); \

#define ERROR(FMT,ARG...) \
fprintf(stderr, ":%s:%d: ERROR: " FMT, __FUNCTION__, __LINE__, ##ARG); \


static char* XoUtil_fileReadAll(const char *path, int *status, unsigned int max_len)
{
	int fd;
	ssize_t read_size = 0;
	const int read_chunk_size = 4095;
	size_t bytes_read = 0;
	char *buffer = NULL;
	int buffer_size;

	*status = 0; // init

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		DBG("Error opening '%s' \n", path);
		*status = errno;
		return NULL;;
	}
	do {
		buffer_size = bytes_read + read_chunk_size;
		buffer = realloc(buffer, buffer_size+1);
		read_size = read(fd, buffer+bytes_read, read_chunk_size);
		if (read_size == -1) {
			DBG("Error reading file: %d \n", errno);
			*status = -1;
			break;
		}
		bytes_read += read_size;
		buffer[bytes_read]  = 0; // null terminate
	} while (read_size != 0  && bytes_read < max_len);

	buffer[buffer_size-1] = 0; // ensure null terminated

	close(fd);
	return buffer;

}

gcry_sexp_t load_sexp_from_file(const char *filename)
{
	const int key_maxlen = 4095;
	char *sexp_str = NULL;
	char *p = NULL;
	int status = 0;
	char buff[512] =  {0 ,};
	char read_path[512] =  {0 ,};
	gcry_sexp_t sexp = NULL;
	size_t erroff = 0;
	int ret = 0;

	// load in current dir
	sexp_str = XoUtil_fileReadAll(filename, &status, key_maxlen);
	if (sexp_str)
		goto process_sexp;

	ret = readlink("/proc/self/exe", buff, sizeof(buff)-1);
	if (ret > 4) {
		DBG("self=%s\n", buff);
		p = dirname(buff);
		DBG("dirname=%s  buffsize=%zd\n", p, sizeof(buff));
		snprintf(read_path, sizeof(read_path)-1, "%s/%s", p, filename);
		DBG("path=%s\n", read_path);
		sexp_str = XoUtil_fileReadAll(read_path, &status, key_maxlen);
		if (sexp_str)
			goto process_sexp;

	}

	snprintf(buff, sizeof(buff)-1, "/tmp/%s", filename);
	sexp_str = XoUtil_fileReadAll(buff, &status, key_maxlen);

	process_sexp:
	if (sexp_str) {

		ret = gcry_sexp_sscan(&sexp, &erroff, sexp_str, strlen(sexp_str));

		if (ret) {
			ERROR("private key sexp not not valid %d at %zd : %s\n", ret, erroff, sexp_str);
			free(sexp_str);
			return NULL;
		}

		free(sexp_str);
		sexp_str = NULL;
		return sexp;
	}

	return NULL;
}


/**
 * @brief calculate SHA256 of a file
 *
 * @param filename ...
 * @param skip_remainder don't include X bytes at end of file
 * @param digest_ascii pointer to hold result must be at least 65 bytes.   SHA256 is 32bytes * 2 (hex ascii expansion) + 1 NULL
 * @return int
 */

int get_sha256(const char *filename, unsigned long skip_remainder, char *digest_ascii_hex)
{
	struct stat stat;
	void *data;
	int fd;
	int sha256_digest_length = gcry_md_get_algo_dlen (GCRY_MD_SHA256);
	gcry_md_hd_t  md_hd;
	gcry_error_t  md_err;
	unsigned char *digest = NULL;
	int i;

	DBG("Opening firmware: '%s'\n", filename);
	fd = open(filename, O_RDONLY);
	if (fd == -1) {
		ERROR("opening '%s' errno=%d \n", filename, errno);
		return -errno;
	}

	if ( (fstat(fd, &stat) == -1) ) {
		ERROR("Stat of file failed: %s\n", strerror(errno));
		return -errno;
	}

	if (stat.st_size < 1024) {
		ERROR("Image file too small to be valid = %zd\n",stat.st_size);
		return -errno;
	}

	// map file to memory
	data = mmap(NULL, stat.st_size, PROT_READ , MAP_SHARED, fd, 0);
	if (data == MAP_FAILED) {
		ERROR("Not enough memory mmap failed\n");
		return -errno;
	}
	close(fd);

	md_err = gcry_md_open(&md_hd, GCRY_MD_SHA256, 0);
	if (md_err) {
		ERROR("error calling gcry_md_open()\n");
	}

	gcry_md_write(md_hd, data, stat.st_size - skip_remainder); // hash all except sig

	// get digest
	digest = gcry_md_read (md_hd, GCRY_MD_SHA256);

	for (i=0; i < sha256_digest_length; i++) {
		sprintf(digest_ascii_hex+(i*2), "%02X", digest[i]);
	}
	digest_ascii_hex[sha256_digest_length*2] = '\0';

	DBG("sha256 is  %s\n", digest_ascii_hex);
	munmap(data, stat.st_size);
	return 0;
}


/* EOF */
