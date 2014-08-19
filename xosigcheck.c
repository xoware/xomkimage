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
#include <endian.h>

#define PROG_NAME "xosigcheck"

#define ERROR(FMT,ARG...) \
	fprintf(stderr, PROG_NAME ":%s:%d: ERROR: " FMT, __FUNCTION__, __LINE__, ##ARG);

#define DBG(FMT,ARG...) \
	fprintf(stderr, PROG_NAME ":%s:%d: " FMT, __FUNCTION__, __LINE__, ##ARG); \

void print_usage(const char *exe_name)
{
	printf("usage:  %s -t <type> -f <file.img>\n", exe_name);
	exit(EXIT_FAILURE);
}

#define SIG_SIZE 256

#define DATA_SEXP_FORMAT "(data\n (flags pkcs1)\n (hash sha256 #%s#))\n"
#define SIG_VAL_SEXP_FORMAT "(sig-val (rsa (s #%s#)))\n"

// static const char rsa_public_key[] = "(key-data (public-key (rsa "
// "(n #00C0C07F64847605CE7280B920E71047615B924E7D7B73FCA8430AF573D9C1B251D9EF869677EDB854A3C500953268BF71FDF36DD581A949C515CB5058C1B598289359367F424F28E429D9F0EECAF094DFB9484CF657409D0C74C2B1809DEB55761DE84528FAD1F873CA79EAABBB6FED1B347F378703DC0D8A82097FEAA8BBF5AE76AB6B9C311BF7B66DBA9D93E391B0233C00A74DC27F2F591BF8D2EE8AFFF2F81356D14BE6232BB0F65B9BF54B9F82FF8645857C872B6E74E6CDFBBEB41AF6138F7F21547B47DFA1B460ECCCFEF97A36E8ACDDF2E5EC2504648643835201A36065003883B61F9BD2CD904CDA11F981704994389F152C536C2778D2836D36A97F#)"
// "(e #010001#))))";

static const char rsa_public_key[] = "(public-key (rsa "
 " (n #00C22D0C98E34FB872D133CD65FF88FBAAADDA920313EB5069E3217DF067255B4AA9EA0FDF6CCDA73BCB35E0AD1664895D9A141274E62FCCE266B90C0960D363E079CD7099E38B3BCF3D0BD6E01C034B47A3A908E8F5DAC9F8EF1B57F91B871CFCF90F359C98B2D3482AC40F2299B2F7FE1292AF23264207499DAA158D112008A09B5CB5B978FE408AE8300798C08773C8BC47E038F7C6F7427BB1B349A0E89412A4CCD7647AB324BD8DD7B4E586734941B13F6A964A2FF45A84E227DB630AB8D56CE498FABC76F2C89368282DCD5307B8F8A8404964589F51788A9316F92C356A935F357FF887DC4A6FA34D688A9392FCAD2C574857325A71D164C97DC6F241B9#) "
 " (e #010001#) )	) ";


typedef long long               squashfs_block;
typedef long long               squashfs_inode;

struct squashfs_super_block {
	unsigned int            s_magic;  // 0
	unsigned int            inodes; // 4
	unsigned int            mkfs_time /* time of filesystem creation */;  // 8
	unsigned int            block_size; // 12
	unsigned int            fragments; // 16
	unsigned short          compression; // 20
	unsigned short          block_log; // 22
	unsigned short          flags; // 24
	unsigned short          no_ids; // 26
	unsigned short          s_major; // 28
	unsigned short          s_minor; // 30
	squashfs_inode          root_inode; //32
	long long               bytes_used; // 40
	long long               id_table_start; // 48
	long long               xattr_id_table_start;
	long long               inode_table_start;
	long long               directory_table_start;
	long long               fragment_table_start;
	long long               lookup_table_start;
};


bool is_signature_ok(const char *digest_ascii, const unsigned char *signature)
	{
		gcry_sexp_t public_key = NULL;
		gcry_sexp_t sig_val = NULL;
		gcry_sexp_t sha_data = NULL;
		size_t erroff;
		char signature_ascii[(SIG_SIZE*2) +1];
		char signature_sexp_ascii[600];
		char sha_data_ascii[256];
		gcry_error_t ret;
		int i;
		bool sig_valid = false;

		ret = gcry_sexp_sscan(&public_key, &erroff, rsa_public_key, strlen(rsa_public_key));
		if (ret) {
			ERROR("public key sexp not not valid %d at %zd : %s\n", ret, erroff, rsa_public_key);
			return false;
		}

		snprintf(sha_data_ascii, sizeof(sha_data_ascii) -1, DATA_SEXP_FORMAT, digest_ascii);
		DBG("data = %s\n", sha_data_ascii);
		// 	ret = gcry_sexp_build(&sha_data, &erroff, DATA_SEXP_FORMAT, digest_ascii);
		ret = gcry_sexp_sscan(&sha_data, &erroff, sha_data_ascii, strlen(sha_data_ascii));
		if (ret) {
			ERROR("data sexp not not valid %d at %zd : %s\n", ret, erroff, sha_data_ascii);
			return false;
		}

		// build ASCII of signature 256
		for (i = 0; i < SIG_SIZE; i++) {
			sprintf(signature_ascii+(i*2), "%02X", signature[i]);
		}
		signature_ascii[SIG_SIZE*2] = 0; // null term

		// 	ret = gcry_sexp_build(&sig_val, &erroff, SIG_VAL_SEXP_FORMAT, signature_ascii);
		snprintf(signature_sexp_ascii, sizeof(signature_sexp_ascii) -1, SIG_VAL_SEXP_FORMAT, signature_ascii);

		DBG("Signature (%zd) = %s\n", strlen(signature_sexp_ascii), signature_sexp_ascii);
		ret = gcry_sexp_sscan(&sig_val, &erroff, signature_sexp_ascii, strlen(signature_sexp_ascii));
		if (ret) {
			ERROR("signature sexp not not valid %d at %zd : %s\n", ret, erroff, signature_sexp_ascii);
			return false;
		}


		ret = gcry_pk_verify (sig_val, sha_data, public_key);
		if (ret) {
			ERROR("Signature verify error %d = %s \n", ret, gcry_strerror(ret));
		} else {
			sig_valid = true;
			DBG("Signature verified good!\n");
		}

		if (public_key)
			gcry_sexp_release(public_key);

		if (sig_val)
			gcry_sexp_release(sig_val);

		if (sha_data)
			gcry_sexp_release(sha_data);

		return sig_valid;
}

#define BUFF_SIZE 512
#define SQUASHFS_MAGIC                  0x73717368

int check_squashfs_sig(const char *filename)
{
	unsigned char buffer[BUFF_SIZE] = {0,};
	char digest_ascii[66] = {0,};
	struct stat stat;
	void *data;
	int fd;
	int sha256_digest_length = gcry_md_get_algo_dlen (GCRY_MD_SHA256);
	gcry_md_hd_t  md_hd;
	gcry_error_t  md_err;
	unsigned char *digest = NULL;
	int i;
	int pad_size;
	struct squashfs_super_block *sblk = NULL;

// 	DBG("Opening firmware: '%s'\n", filename);
	fd = open(filename, O_RDONLY);
	if (fd == -1) {
		ERROR("opening '%s' errno=%d \n", filename, errno);
		return -errno;
	}

	i = read(fd, buffer, BUFF_SIZE);

	if (i != BUFF_SIZE) {
		ERROR("Read ERROR\n");
		exit(EXIT_FAILURE);
	}
	sblk = (struct squashfs_super_block *) buffer;
	if (sblk->s_magic != SQUASHFS_MAGIC) {
		ERROR("SquashFS not detected\n");
		exit(EXIT_FAILURE);
	}
	stat.st_size = le64toh(sblk->bytes_used);
// 	DBG("Size is = %zd\n", stat.st_size);
	pad_size = 4096 - (stat.st_size & 4095);

	stat.st_size += pad_size + SIG_SIZE;
// 	DBG("Size is now = %zd\n", stat.st_size);


	if (stat.st_size < (2 * 1024*1024)) {
		ERROR("Image file too small to be valid %zd\n", stat.st_size);
		exit(EXIT_FAILURE);
	}

// NOTE tried to mmap before but you can't mmap the /dev/mtdX  when it's a NAND device
// 	data = mmap(NULL, stat.st_size, PROT_READ , MAP_SHARED, fd, 0);
	lseek(fd, 0, SEEK_SET); // rewind file
	data = malloc(stat.st_size);
	i = read(fd, data, stat.st_size);
	if (i != stat.st_size) {
		ERROR("Read of file failed read=%d  size=%zd", i, stat.st_size);
		exit(EXIT_FAILURE);
	}

	close(fd);

	md_err = gcry_md_open(&md_hd, GCRY_MD_SHA256, 0);
	if (md_err) {
		ERROR("error calling gcry_md_open()\n");
	}

	gcry_md_write(md_hd, data, stat.st_size - SIG_SIZE); // hash all except sig

	// get MD5 digest
	digest = gcry_md_read (md_hd, GCRY_MD_SHA256);

	for (i=0; i < sha256_digest_length; i++) {
		sprintf(digest_ascii+(i*2), "%02X", digest[i]);
	}
	digest_ascii[sha256_digest_length*2] = '\0';

// 	DBG("sha256 is  %s\n", digest_ascii);


	if (is_signature_ok(digest_ascii, data + stat.st_size - SIG_SIZE)) {
		exit(EXIT_SUCCESS);
	}

	exit(EXIT_FAILURE);


	return 0;
}

int main(int argc, char *argv[]) 
{
	int opt;
	const char * filename = NULL;

	if (argc < 3) {
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
	check_squashfs_sig(filename);


	return EXIT_SUCCESS;
}