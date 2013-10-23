
#include <efi.h>
#include <efivar.h>
#include <fcntl.h>
#include <openssl/bio.h>
#include <openssl/objects.h>
#include <openssl/pkcs7.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <string.h>

#include "PeImage.h"
#include "crypto.h"
#include "pe.h"
#include "wincert.h"

void
print_hex(uint8_t *data, size_t data_size)
{
	for (unsigned int i = 0; i < data_size; i++)
		printf("%02x", data[i]);
	printf("\n");
}


/**
Verification callback function to override any existing callbacks in OpenSSL
for intermediate certificate supports.

@param[in]  Status   Original status before calling this callback.
@param[in]  Context  X509 store context.

@retval     1        Current X509 certificate is verified successfully.
@retval     0        Verification failed.

**/
int
X509VerifyCb (
IN int            Status,
IN X509_STORE_CTX *Context
)
{
X509_OBJECT  *Obj;
INTN         Error;
INTN         Index;
INTN         Count;

Obj   = NULL;
Error = (INTN) X509_STORE_CTX_get_error (Context);

//
// X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT and X509_V_ERR_UNABLE_TO_GET_ISSUER_
// CERT_LOCALLY mean a X509 certificate is not self signed and its issuer
// can not be found in X509_verify_cert of X509_vfy.c.
// In order to support intermediate certificate node, we override the
// errors if the certification is obtained from X509 store, i.e. it is
// a trusted ceritifcate node that is enrolled by user.
// Besides,X509_V_ERR_CERT_UNTRUSTED and X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE
// are also ignored to enable such feature.
//
if ((Error == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT) ||
    (Error == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY)) {
  Obj = (X509_OBJECT *) malloc (sizeof (X509_OBJECT));
  if (Obj == NULL) {
    return 0;
  }

  Obj->type      = X509_LU_X509;
  Obj->data.x509 = Context->current_cert;

  CRYPTO_w_lock (CRYPTO_LOCK_X509_STORE);

  if (X509_OBJECT_retrieve_match (Context->ctx->objs, Obj)) {
    Status = 1;
  } else {
    //
    // If any certificate in the chain is enrolled as trusted certificate,
    // pass the certificate verification.
    //
    if (Error == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY) {
      Count = (INTN) sk_X509_num (Context->chain);
      for (Index = 0; Index < Count; Index++) {
	Obj->data.x509 = sk_X509_value (Context->chain, (int) Index);
	if (X509_OBJECT_retrieve_match (Context->ctx->objs, Obj)) {
	  Status = 1;
	  break;
	}
      }
    }
  }

  CRYPTO_w_unlock (CRYPTO_LOCK_X509_STORE);
}

if ((Error == X509_V_ERR_CERT_UNTRUSTED) ||
    (Error == X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE)) {
  Status = 1;
}

if (Obj != NULL) {
  OPENSSL_free (Obj);
}

return Status;
}

PKCS7 *
make_pkcs7(PE_COFF_LOADER_IMAGE_CONTEXT *context,
	uint8_t *bin, size_t size)
{
	WIN_CERTIFICATE_EFI_PKCS *cert = NULL;
	size_t cert_size = 0;

	if (context->SecDir->Size != 0) {
		cert = ImageAddress(bin, size, context->SecDir->VirtualAddress);

		if (!cert) {
			fprintf(stderr, "signature is at invalid offset\n");
			exit(1);
		}
		cert_size = context->SecDir->Size - sizeof (cert->Hdr);
	}

	BIO *Pkcs7Bio = BIO_new(BIO_s_mem());
	if (!Pkcs7Bio) {
		fprintf(stderr, "BIO_new()\n");
		exit(1);
	}

	int rc = BIO_write(Pkcs7Bio, &cert->CertData, cert_size);

	PKCS7 *Pkcs7 = d2i_PKCS7_bio(Pkcs7Bio, NULL);
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
verify_pkcs7(PKCS7 *Pkcs7, uint8_t *ImageHash, size_t HashSize)
{
	UINT8 *SpcIndirectDataOid;
	UINT8 mSpcIndirectOidValue[] = {
		0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x04
		};

	SpcIndirectDataOid = (UINT8 *)(Pkcs7->d.sign->contents->type->data);
	if (memcmp(SpcIndirectDataOid, mSpcIndirectOidValue,
				        sizeof (mSpcIndirectOidValue)) != 0) {
		fprintf(stderr, "Wrong OID on content\n");
		exit(1);
	}

	UINT8 Asn1Byte;
	UINTN ContentSize;
	UINT8 *SpcIndirectDataContent;

	SpcIndirectDataContent = (UINT8 *)(Pkcs7->d.sign->contents->d.other->value.asn1_string->data);

	Asn1Byte = *(SpcIndirectDataContent + 1);
	if ((Asn1Byte & 0x80) == 0) {
		ContentSize = (UINTN) (Asn1Byte & 0x7F);
		SpcIndirectDataContent += 2;
	} else if ((Asn1Byte & 0x82) == 0x82) {
		ContentSize  = (UINTN) (*(SpcIndirectDataContent + 2));
		ContentSize = (ContentSize << 8) + (UINTN)(*(SpcIndirectDataContent + 3));
		SpcIndirectDataContent += 4;
	} else {
		fprintf(stderr, "ASN.1 is bad\n");
		exit(1);
	}

	if (memcmp(SpcIndirectDataContent + ContentSize - HashSize,
			ImageHash, HashSize) != 0) {
		fprintf(stderr, "Hashes do not match:\n");
		print_hex(SpcIndirectDataContent + ContentSize - HashSize, HashSize);
		print_hex(ImageHash, HashSize);
		exit(1);
	}

	return 0;
}
