
#include <efi.h>
#include <openssl/bio.h>
#include <openssl/objects.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

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




