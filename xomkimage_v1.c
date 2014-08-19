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

#include "xomkimage.h"
#include "signing-common.h"



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
	
const char *PartTypeStr[] = {
	"invalid",
	"mtd",
	"ubivol",
	"raw",
	"file",
	"last",
	NULL
};

const char *ProductTypeStr[] = {
	"invalid",
	"ExoKey_v1",
	"ExoNet_xo1",
	"raw",
	"file",
	"last",
	NULL
};
/*
static const char rsa_private_key[] = "(key-data"
"(public-key"
"(rsa"
"(n #00C0C07F64847605CE7280B920E71047615B924E7D7B73FCA8430AF573D9C1B251D9EF869677EDB854A3C500953268BF71FDF36DD581A949C515CB5058C1B598289359367F424F28E429D9F0EECAF094DFB9484CF657409D0C74C2B1809DEB55761DE84528FAD1F873CA79EAABBB6FED1B347F378703DC0D8A82097FEAA8BBF5AE76AB6B9C311BF7B66DBA9D93E391B0233C00A74DC27F2F591BF8D2EE8AFFF2F81356D14BE6232BB0F65B9BF54B9F82FF8645857C872B6E74E6CDFBBEB41AF6138F7F21547B47DFA1B460ECCCFEF97A36E8ACDDF2E5EC2504648643835201A36065003883B61F9BD2CD904CDA11F981704994389F152C536C2778D2836D36A97F#)"
"(e #010001#)"
")"
")"
"(private-key"
"(rsa"
"(n #00C0C07F64847605CE7280B920E71047615B924E7D7B73FCA8430AF573D9C1B251D9EF869677EDB854A3C500953268BF71FDF36DD581A949C515CB5058C1B598289359367F424F28E429D9F0EECAF094DFB9484CF657409D0C74C2B1809DEB55761DE84528FAD1F873CA79EAABBB6FED1B347F378703DC0D8A82097FEAA8BBF5AE76AB6B9C311BF7B66DBA9D93E391B0233C00A74DC27F2F591BF8D2EE8AFFF2F81356D14BE6232BB0F65B9BF54B9F82FF8645857C872B6E74E6CDFBBEB41AF6138F7F21547B47DFA1B460ECCCFEF97A36E8ACDDF2E5EC2504648643835201A36065003883B61F9BD2CD904CDA11F981704994389F152C536C2778D2836D36A97F#)"
"(e #010001#)"
"(d #200EE4213FB6B17888AAC81FA4CE9C50A0FE5077A654C02CEC19A2814632650A20092A855425018772458DB742CF112850687058165CA59C55E79ED1644663AC3BF5968ECBE486948C3167551003BB7F0A3DF02EF88C1292C3C8ADE50A5EDDB3EB7D7A233AB4397268B6A64531C387D8027F36290A874AE9427F79FAF95D699AF4BDDBEF9AB9E91025D76B386B05DFF1BD634B05F6C88CD89569A591964A52241E414D80EEEE7DEB65EF5FEEE524D85B339B9CEFDCF86CFE3DA5F9F19EAD19C6DF827868C83620535F011B00E0E6742C9BF0033A2EDA9FA9ABDFBAAE072135C5D251A82B6F7BFEA551611750204A1F4EE38B7157D23408A34D5D4EDADBF10A41#)"
"(p #00D34EC0057158587D8A367BD46D2DF7CCA2CB9793B12F813EF57895A9E5FF254498DEB66C01133EC679AB52B496D9A54FC0FBCDC09A301DE45E18473D65481EA54CE0979D696520990AB6EA7177990FB45EB156362D478CB960BBCB86E38E5A8279AC4CB722A45BA7178EC6C702C71F4B867B5D46F1D2347DA077E1643ED25579#)"
"(q #00E9850CF9B45C79B099AF826BCC7BB34638837EED99D92158921C0623F47B94565EA0C9EF7ABAE2A1AEE2509F00679A9BDAEC52D9793C17320EAB91912B87C4D4893BFDD94051F6E55AED5211F8E0B839727B50A2461AE80B9CE365E848E3E747E312AA332C0FBA44B3218AEE56128BA4BDF824A37E1B3475F2EE9E120EA410B7#)"
"(u #28B600E28ABF1CFD3C4E8447CED74D0B6A07AFED631F172B2E234485F400F06A40FCDF2F0BD517A6F06F63095FB2064E24C92836165FC7267228B5ECD3946B6559D98777E87485BE82249905E3AB4AA600FFC8D27C442BF4786871DC9E1A5DC304A36D32A07B21EBF79365ABC3B5C91E4A1324D4C3AC3C2F13866F9697FC1F73#)"
")"
")"
")"
"\n";*/


static void
fatal(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "Fatal: ");
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	exit(EXIT_FAILURE);
}

static void
usage(const char *s)
{
	fprintf(stderr, "Usage: %s HwType this_verion min_version file1:type1:n1:offset:devname:filename [file2:type2:n2:offset:devname:filename ...] > output.img\n", s);
	fprintf(stderr, "where: \n");
	fprintf(stderr, "\tHwType: ExoKey_v1, ExoNet_xo1\n");
	fprintf(stderr, "\tVersion: 2014.01.01\n");
	fprintf(stderr, "\tfile# is a relative path to a binary image\n");
	fprintf(stderr, "\ttype# is partition type (mtd,ubivol,file) \n");
	fprintf(stderr, "\tn# is the partition number, or UBI partition (usually 0  for /dev/ubi0) \n");
	fprintf(stderr, "\tofsset.   Always set to zero unless raw image \n");
	fprintf(stderr, "\tdevname.  /dev/devname   mtdX   or mmcblk0pX \n");
	fprintf(stderr, "\tfilename.  kernel, rootfs  \n");
	fprintf(stderr, "The output file will be printed to stdout\n");
	exit(EXIT_FAILURE);
}
enum PartType PartType_fromAscii(const char *str)
{
	enum PartType ptype = PartType_invalid;
	int i;
	
	for (i = 0; PartTypeStr[i] ; i++) {
		if (strcasestr(str, PartTypeStr[i])) {
			ptype = i;
			return ptype;
		}
	}
	fatal("Invalid type=%s\n", str);
	return PartType_invalid; //will not return but silence warning
}


enum ProductType ProductType_fromAscii(const char *str)
{
	enum PartType ptype = ProductType_invalid;
	int i;

	for (i = 0; ProductTypeStr[i] ; i++) {
		if (strcasestr(str, ProductTypeStr[i])) {
			ptype = i;
			return ptype;
		}
	}
	fatal("Invalid type=%s\n", str);
	return ProductType_invalid; //will not return but silence warning
}
static void
process_arg(const char *__arg, void ***__fmaps, struct ImageHeader **__images, struct GlobalHdr_v1 *hdr)
{
	char *arg = strdup(__arg);
	void **fmaps = *__fmaps;
	struct ImageHeader *images = *__images;
	struct stat st;
	int fd;
	void *fmap;
	char *stringp = arg;
	char *token, *file_name = NULL, *type_str = NULL, *partnum_str = NULL, *offset_str = NULL;
	char *devname = NULL, *filename = NULL;
	int i;
	enum PartType ptype;

	
	if (arg == NULL)
		fatal("Not enough memory\n");
	
	
	for (i = 0; i < 6 ; i++) {
		token = strsep(&stringp, ":");
		if (token == NULL && (i < 5)) {
			ERROR(" too few paramaters see ussage\n");
			usage(PROG_NAME);
		}
		switch (i)
		{
			case 0:
				file_name = token;
			break;
			case 1:
				type_str = token;
			break;
			case 2:
				partnum_str = token;
			break;
			case 3:
				offset_str = token;
				if (atoi(offset_str)) {
					fatal("offset other than 0 not supported yet");
				}
			break;
			case 4:
				devname = token;
				break;
			case 5:
				filename = token;
				break;
			default:
				fatal(" Invalid usage token=%s\n", token);
				break;
				
		}
	}
	
	DBG("file: %s\n", file_name);
	ptype = PartType_fromAscii(type_str);
	DBG("type: %s=%d\n", type_str,ptype);
	DBG("partnum: %s\n", partnum_str);
	DBG("offset: %s\n", offset_str);
	DBG("devname: %s\n", devname);
	if (strlen(devname) > 30) {
		fatal("devname too long:%s\n",devname);
	}
	DBG("filename: %s\n", filename);
	if (strlen(filename) > 30) {
		fatal("filename too long:%s\n",filename);
	}
	
	if ((fd = open(file_name, O_RDONLY)) < 0)
		fatal("Could not open file %s: %s\n", file_name, strerror(errno));
	
	DBG("file: %s\n", file_name);

	if (fstat(fd, &st) < 0)
		fatal("Count not stat file %s: %s\n", file_name, strerror(errno));

	fmap = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	close(fd);

	if (fmap == MAP_FAILED)
		fatal("Count not mmap file %s: %s\n", file_name, strerror(errno));

	hdr->raw_size = htole32(le32toh(hdr->raw_size) + st.st_size); // increment size in global header
	hdr->nimages = htole32(le32toh(hdr->nimages) + 1);
	fmaps = realloc(fmaps, sizeof(void *) * le32toh(hdr->nimages));  // alloc space for pointers to firmware mmaped files

	// realloc space for additional image header
	images = realloc(images, sizeof(struct ImageHeader) * le32toh(hdr->nimages));

	if (fmaps == NULL || images == NULL)
		fatal("Not enough memory\n");

	fmaps[le32toh(hdr->nimages) - 1] = fmap;
	memset(&images[le32toh(hdr->nimages) - 1], 0, sizeof(struct ImageHeader)); // init
	images[le32toh(hdr->nimages) - 1].size = htole32(st.st_size);
	images[le32toh(hdr->nimages) - 1].part_type = htole32(ptype);
	images[le32toh(hdr->nimages) - 1].partition = htole32(strtoul(partnum_str, NULL, 10));
	images[le32toh(hdr->nimages) - 1].offset = htole32(0);
	strcpy(images[le32toh(hdr->nimages) - 1].devname, devname);
	strcpy(images[le32toh(hdr->nimages) - 1].filename, filename);
	
	DBG("size: %d = 0x%x\n", (int) st.st_size, (int) st.st_size);
	
	*__images = images;
	*__fmaps = fmaps;
	free(arg);
}

#if 0
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
	char buff[1024];
	gcry_sexp_t sexp = NULL;
	size_t erroff;
	int ret;

	// load in current dir
	sexp_str = XoUtil_fileReadAll(filename, &status, key_maxlen);
	if (sexp_str)
		goto process_sexp;

	ret = readlink("/proc/self/exe", buff, sizeof(buff)-1);
	if (ret > 4) {
		DBG("self=%s\n", buff);
		p = dirname(buff);
		DBG("dirname=%s\n", p);
		snprintf(buff, sizeof(buff)-1, "/%s/%s", p, filename);
		DBG("path=%s\n", buff);
		sexp_str = XoUtil_fileReadAll(buff, &status, key_maxlen);
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
#endif

#define SEXP_FORMAT "(data\n (flags pkcs1)\n (hash sha256 #%s#))\n"

static int sign_header(struct GlobalHdr_v1 *hdr, const char * digest_ascii)
{
	char blob[256] = {0,};
	char sig[2048] = {0,};
	gcry_sexp_t keydata = NULL;
	gcry_sexp_t sign = NULL;
	gcry_sexp_t private_key  = NULL;
	gcry_sexp_t token = NULL;
	size_t erroff;
	const char *sig_str = NULL;
	char *private_key_str = NULL;
	int ret;
	size_t len;

	sprintf(blob, SEXP_FORMAT, digest_ascii);
	ret = gcry_sexp_sscan(&keydata, &erroff, blob, strlen(blob));
	if (ret) {
		ERROR("sexp not not valid at %zd : %s\n", erroff, blob);
		ret = EXIT_FAILURE;
		goto free_mem;
	}
	private_key = load_sexp_from_file("mkimage-key.sexp");
	if (!private_key) {
		ERROR("Error loading private key.  Must have private key in your working dir, bin dir, or /tmp\n");
		ret = EXIT_FAILURE;
		goto free_mem;
	}

	ret = gcry_pk_testkey(private_key);
	if (ret) {
		ERROR("private key not valid\n");
		ret = EXIT_FAILURE;
		goto free_mem;
	}

	ret = gcry_pk_sign(&sign, keydata, private_key);
	if (ret) {
		ERROR("signing error %d %s\n",  ret, gcry_strerror(ret));
		ret = EXIT_FAILURE;
		goto free_mem;
	}

	len = gcry_sexp_sprint(sign, GCRYSEXP_FMT_ADVANCED, sig, 2048);

	if (len < 0) {
		ERROR("sexp print \n");
		ret = EXIT_FAILURE;
		goto free_mem;
	}
	DBG("sig=%s\n", sig);

	token = gcry_sexp_find_token(sign, "s", 1);
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
	memcpy(hdr->signature, sig_str, 256);
	ret = 0; // OK
	free_mem:

	if (keydata)
		gcry_sexp_release(keydata);

	if (sign)
		gcry_sexp_release(sign);

	if (private_key)
		gcry_sexp_release(private_key);

	if (token)
		gcry_sexp_release(token);

	if (private_key_str)
		free(private_key_str);

	return ret;
}

int
main(int argc, char *argv[])
{
	void **fmaps = NULL;
	struct GlobalHdr_v1 hdr;
	struct ImageHeader *images = NULL;
	struct termios tios;
	int i;
	int sha256_digest_length = gcry_md_get_algo_dlen (GCRY_MD_SHA256);
	ssize_t written;
	gcry_md_hd_t  md_hd;
	gcry_error_t  md_err;
	unsigned char *digest = NULL;
	char  digest_ascii[128] = {0,};
	const char* this_version;
	const char* min_version;
	enum ProductType product_type;
	int ret;


	if (argc < 4) {
		ERROR("not enough args %d\n", argc);
		usage(argv[0]);
	}

	if (tcgetattr(1, &tios) == 0)
		fatal("Won't write binary data to a terminal\n");

	memset(&hdr, 0, sizeof(struct GlobalHdr_v1));

	product_type = ProductType_fromAscii(argv[1]);
	if (product_type == ProductType_invalid) {
		ERROR("Invalid product type\n");
		usage(argv[0]);
	}

	this_version = argv[2];
	if (!this_version || !strstr(this_version, ".") || strlen(this_version) > 31) {
		ERROR("Invalid this version \n");
		usage(argv[0]);
	}
	min_version = argv[3];
	if (!min_version || !strstr(min_version, ".") || strlen(min_version) > 31) {
		ERROR("Invalid min version \n");
		usage(argv[0]);
	}

	hdr.hdr_version = htole32(1);
	hdr.nimages = 0;
	hdr.raw_size = 0;
	hdr.product_type_code = htole32(product_type);
	strcpy(hdr.this_version, this_version);
	strcpy(hdr.min_version, min_version);

	for (i = 4; i < argc; i++) {
		if (strchr(argv[i], ':') == NULL)
			usage(argv[0]);

		process_arg(argv[i], &fmaps, &images, &hdr);
	}

	md_err = gcry_md_open (&md_hd, GCRY_MD_SHA256, 0);
	DBG("offset of sha =%ld\n",offsetof(struct GlobalHdr_v1, sha256));

	gcry_md_write (md_hd, &hdr, offsetof(struct GlobalHdr_v1, sha256)); // hash image header

	for (i = 0; i < le32toh(hdr.nimages); i++) {
		gcry_md_write (md_hd, &images[i], sizeof(struct ImageHeader)); // hash image header
	}
	for (i = 0; i < le32toh(hdr.nimages); i++) {
		gcry_md_write (md_hd, fmaps[i], le32toh(images[i].size)); // hash image
	}


	// Finalize string addition -> create digest
	md_err = gcry_md_final (md_hd);

	if (md_err) {
		ERROR("gcry_md_final error: %s\n", gcry_strerror(md_err));
		gcry_md_close (md_hd);
		return EXIT_FAILURE;
	}
	// get MD5 digest
	digest = gcry_md_read (md_hd, GCRY_MD_SHA256);

	for (i=0; i< sha256_digest_length; i++) {
		sprintf(digest_ascii+(i*2), "%02X", digest[i]);
		hdr.sha256[i] = digest[i];
	}
	digest_ascii[sha256_digest_length*2] = '\0';
	DBG("Calc digest=%s\n",digest_ascii);

	ret = sign_header(&hdr, digest_ascii);
	if (ret == EXIT_FAILURE)
		return EXIT_FAILURE;

	written = write(STDOUT_FILENO, &hdr, sizeof(hdr));
	if (written == -1) {
		ERROR("Writing header: %d : %m\n", errno);
	}
	written = write(STDOUT_FILENO, images, sizeof(struct ImageHeader) * le32toh(hdr.nimages));
	if (written == -1) {
		ERROR("Writing image header: %d : %m\n", errno);
	}
	errno = 0;
	for (i = 0; i < le32toh(hdr.nimages); i++) {
		written = write(STDOUT_FILENO, fmaps[i], le32toh(images[i].size));
		DBG("Writing image=%d: written= %zd size=%d : %d %m\n", i, written, le32toh(images[i].size), errno);
		munmap(fmaps[i], le32toh(images[i].size));
	}

	free(fmaps);
	free(images);
	gcry_md_close (md_hd);
	exit(EXIT_SUCCESS);
}

/* EOF */
