#ifndef SIGNING_COMMON_H
#define SIGNING_COMMON_H

gcry_sexp_t load_sexp_from_file(const char *filename);

int get_sha256(const char *filename, unsigned long skip_remainder, char *digest_ascii_hex);

#endif