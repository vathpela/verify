
#include <efi.h>
#include <efivar.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/bio.h>
#include <openssl/err.h>
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

UINT8 mOidValue[9] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02 };

/**
  Check input P7Data is a wrapped ContentInfo structure or not. If not construct
  a new structure to wrap P7Data.

  Caution: This function may receive untrusted input.
  UEFI Authenticated Variable is external input, so this function will do basic
  check for PKCS#7 data structure.

  @param[in]  P7Data       Pointer to the PKCS#7 message to verify.
  @param[in]  P7Length     Length of the PKCS#7 message in bytes.
  @param[out] WrapFlag     If TRUE P7Data is a ContentInfo structure, otherwise
                           return FALSE.
  @param[out] WrapData     If return status of this function is TRUE: 
                           1) when WrapFlag is TRUE, pointer to P7Data.
                           2) when WrapFlag is FALSE, pointer to a new ContentInfo
                           structure. It's caller's responsibility to free this
                           buffer.
  @param[out] WrapDataSize Length of ContentInfo structure in bytes.

  @retval     TRUE         The operation is finished successfully.
  @retval     FALSE        The operation is failed due to lack of resources.

**/
BOOLEAN
WrapPkcs7Data (
  IN  CONST UINT8  *P7Data,
  IN  UINTN        P7Length,
  OUT BOOLEAN      *WrapFlag,
  OUT UINT8        **WrapData,
  OUT UINTN        *WrapDataSize
  )
{
  BOOLEAN          Wrapped;
  UINT8            *SignedData;

  //
  // Check whether input P7Data is a wrapped ContentInfo structure or not.
  //
  Wrapped = FALSE;
  if ((P7Data[4] == 0x06) && (P7Data[5] == 0x09)) {
    if (memcmp (P7Data + 6, mOidValue, sizeof (mOidValue)) == 0) {
      if ((P7Data[15] == 0xA0) && (P7Data[16] == 0x82)) {
        Wrapped = TRUE;
      }
    }
  }

  if (Wrapped) {
    *WrapData     = (UINT8 *) P7Data;
    *WrapDataSize = P7Length;
  } else {
    //
    // Wrap PKCS#7 signeddata to a ContentInfo structure - add a header in 19 bytes.
    //
    *WrapDataSize = P7Length + 19;
    *WrapData     = malloc (*WrapDataSize);
    if (*WrapData == NULL) {
      *WrapFlag = Wrapped;
      return FALSE;
    }

    SignedData = *WrapData;

    //
    // Part1: 0x30, 0x82.
    //
    SignedData[0] = 0x30;
    SignedData[1] = 0x82;

    //
    // Part2: Length1 = P7Length + 19 - 4, in big endian.
    //
    SignedData[2] = (UINT8) (((UINT16) (*WrapDataSize - 4)) >> 8);
    SignedData[3] = (UINT8) (((UINT16) (*WrapDataSize - 4)) & 0xff);

    //
    // Part3: 0x06, 0x09.
    //
    SignedData[4] = 0x06;
    SignedData[5] = 0x09;

    //
    // Part4: OID value -- 0x2A 0x86 0x48 0x86 0xF7 0x0D 0x01 0x07 0x02.
    //
    memcpy (SignedData + 6, mOidValue, sizeof (mOidValue));

    //
    // Part5: 0xA0, 0x82.
    //
    SignedData[15] = 0xA0;
    SignedData[16] = 0x82;

    //
    // Part6: Length2 = P7Length, in big endian.
    //
    SignedData[17] = (UINT8) (((UINT16) P7Length) >> 8);
    SignedData[18] = (UINT8) (((UINT16) P7Length) & 0xff);

    //
    // Part7: P7Data.
    //
    memcpy (SignedData + 19, P7Data, P7Length);
  }

  *WrapFlag = Wrapped;
  return TRUE;
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
	uint8_t **cert_r, size_t *cert_size_r,
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
	*cert_r = (uint8_t *)&cert->CertData;
	*cert_size_r = cert_size;

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
verify_pkcs7(PKCS7 *Pkcs7, uint8_t *ImageHash, size_t HashSize,
		uint8_t *cert, size_t cert_size, X509_STORE *CertStore)
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

#if 0
	BOOLEAN Wrapped;
	UINT8 *SignedData;
	UINTN SignedDataSize;
	WrapPkcs7Data(cert, cert_size, &Wrapped, &SignedData, &SignedDataSize);
#endif

	CertStore->verify_cb = X509VerifyCb;

	BIO *DataBio;
	DataBio = BIO_new(BIO_s_mem());
	int fd = open("tmp", O_CREAT|O_TRUNC|O_WRONLY);
	write(fd, SpcIndirectDataContent, ContentSize);
	close(fd);
	BIO_write(DataBio, SpcIndirectDataContent, ContentSize);

	ERR_load_PKCS7_strings();
	ERR_load_crypto_strings();
	int rc;
	rc = PKCS7_verify(Pkcs7, NULL, CertStore, DataBio, NULL,
		PKCS7_BINARY
//		|PKCS7_NOVERIFY
//		|PKCS7_NOCHAIN
//		|PKCS7_NOSIGS
		);
	if (rc != 1) {
		char errbuf[120];
		unsigned long err = ERR_get_error();
		ERR_error_string(err, errbuf);
		printf("%s\n", errbuf);
	}

	PKCS7_free(Pkcs7);

	return rc;
}
