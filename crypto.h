#ifndef CRYPTO_H
#define CRYPTO_H 1

#include <openssl/bio.h>
#include <openssl/objects.h>
#include <openssl/pkcs7.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include "PeImage.h"

extern void
print_hex(uint8_t *data, size_t data_size);

extern int
X509VerifyCb(int Status, X509_STORE_CTX *Context);

extern int
verify_pkcs7(PE_COFF_LOADER_IMAGE_CONTEXT *context,
	uint8_t *bin, size_t bin_size,
	uint8_t *ImageHash, size_t HashSize,
	X509_STORE *CertStore);

#endif /* CRYPTO_H */
