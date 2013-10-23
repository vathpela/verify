
#include <fcntl.h>
#include <err.h>
#include <efi.h>
#include <efivar.h>
#include <openssl/bio.h>
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

struct _cert_list_entry;
typedef struct _cert_list_entry {
	uint8_t *cert;
	size_t size;
	struct _cert_list_entry *next;
} cert_list_entry;

static void
add_cert(cert_list_entry **db, int fd)
{
	struct stat sb;
	fstat(fd, &sb);

	void *addr = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (!addr)
		err(1, "verify");

	void *cert = malloc(sb.st_size);
	if (!cert)
		err(1, "verify");

	memcpy(cert, addr, sb.st_size);
	munmap(addr, sb.st_size);

	cert_list_entry *cle = malloc(sizeof (*cle));
	if (!cle)
		err(1, "verify");

	cle->cert = cert;
	cle->size = sb.st_size;
	cle->next = *db;
	*db = cle;
}

static PKCS7 *
make_pkcs7(uint8_t *bin, size_t size)
{
	WIN_CERTIFICATE_EFI_PKCS *cert = NULL;
	size_t cert_size = 0;
	int rc = get_data_dictionary(bin, size, &cert, &cert_size);
	if (rc < 0)
		exit(1);
	
	PKCS7 *Pkcs7 = d2i_PKCS7(NULL, (const unsigned char **)&cert->CertData,
				cert_size);
	if (!Pkcs7) {
		fprintf(stderr, "d2i_PKCS7()\n");
		exit(1);
	}

	if (!PKCS7_type_is_signed(Pkcs7)) {
		fprintf(stderr, "PKCS7 data is not signed.  WTH?\n");
		exit(1);
	}

	return Pkcs7;
}

int
main(int argc, char *argv[])
{
	if (argc < 3) {
		fprintf(stderr, "usage: verify foo.efi cert0 [... certN]\n");
		exit(1);
	}

	int binfd = open(argv[1], O_RDONLY);
	if (binfd < 0)
		err(1, "verify: %s", argv[1]);

	cert_list_entry *certdb = NULL;
	for (int i = 2; argv[i] != NULL; i++) {
		int certfd = open(argv[2], O_RDONLY);
		if (certfd < 0)
			err(1, "verify: %s", argv[i]);
		add_cert(&certdb, certfd);
		close(certfd);
	}

	if (!certdb) {
		fprintf(stderr, "verify: no trusted certificates\n");
		exit(1);
	}

	struct stat sb;
	fstat(binfd, &sb);
	void *bin = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, binfd, 0);

	PKCS7 *Pkcs7 = make_pkcs7(bin, sb.st_size);

	X509_STORE *CertStore = X509_STORE_new();
	if (!CertStore) {
		fprintf(stderr, "X509_STORE_new()\n");
		exit(1);
	}

	cert_list_entry *cle = certdb;
	while (cle) {
		BIO *CertBio = BIO_new(BIO_s_mem());
		if (!CertBio) {
			fprintf(stderr, "BIO_new()\n");
			exit(1);
		}
		
		int rc = BIO_write (CertBio, cle->cert, cle->size);
		if (rc <= 0) {
			fprintf(stderr, "BIO_write()\n");
			exit(1);
		}
		X509 *Cert = d2i_X509_bio(CertBio, NULL);
		if (!Cert) {
			fprintf(stderr, "d2i_X509_bio()\n");
			exit(1);
		}

		if (!(X509_STORE_add_cert(CertStore, Cert))) {
			fprintf(stderr, "X509_STORE_add_cert()\n");
			exit(1);
		}
	}

		CertStore->verify_cb = X509VerifyCb;



	return 0;
}
