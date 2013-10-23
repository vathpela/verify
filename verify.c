
#include <fcntl.h>
#include <err.h>
#include <efi.h>
#include <efivar.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "crypto.h"
#include "pe.h"
#include "wincert.h"

int
main(int argc, char *argv[])
{
	if (argc < 3) {
		fprintf(stderr, "usage: verify foo.efi cert0 [... certN]\n");
		exit(1);
	}

	OpenSSL_add_all_algorithms();
	ERR_load_PKCS7_strings();
	ERR_load_crypto_strings();

	int binfd = open(argv[1], O_RDONLY);
	if (binfd < 0)
		err(1, "verify: %s", argv[1]);

	X509_STORE *CertStore = X509_STORE_new();
	if (!CertStore) {
		fprintf(stderr, "X509_STORE_new()\n");
		exit(1);
	}


	for (int i = 2; argv[i] != NULL; i++) {
		int fd = open(argv[i], O_RDONLY);
		if (fd < 0)
			err(1, "verify: %s", argv[i]);
		printf("adding cert from \"%s\"\n", argv[i]);

		uint8_t *cert;
		struct stat sb;

		fstat(fd, &sb);
		cert = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

		BIO *CertBio = BIO_new(BIO_s_mem());
		if (!CertBio) {
			fprintf(stderr, "BIO_new()\n");
			exit(1);
		}

		int rc = BIO_write (CertBio, cert, sb.st_size);
		if (rc <= 0) {
			fprintf(stderr, "BIO_write()\n");
			exit(1);
		}

		munmap(cert, sb.st_size);
		X509 *Cert = d2i_X509_bio(CertBio, NULL);
		if (!Cert) {
			fprintf(stderr, "d2i_X509_bio()\n");
			exit(1);
		}

		if (!(X509_STORE_add_cert(CertStore, Cert))) {
			fprintf(stderr, "X509_STORE_add_cert()\n");
			exit(1);
		}

		close(fd);
	}

	struct stat sb;
	fstat(binfd, &sb);
	void *bin = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, binfd, 0);

	PE_COFF_LOADER_IMAGE_CONTEXT context;
	int rc = read_header(bin, sb.st_size, &context);
	if (rc < 0) {
		fprintf(stderr, "read_header(): %m\n");
		exit(1);
	}

	UINT8 sha256hash[32];
	rc = generate_hash(bin, sb.st_size, &context, sha256hash);
	if (rc < 0) {
		fprintf(stderr, "you can't handle a hash\n");
		exit(1);
	}

	rc = verify_pkcs7(&context, bin, sb.st_size, sha256hash, 32, CertStore);
	if (!rc) {
		fprintf(stderr, "verify failed!\n");
		exit(1);
	}
	printf("Image verifies correctly\n");

	return 0;
}
