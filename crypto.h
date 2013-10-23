#ifndef CRYPTO_H
#define CRYPTO_H 1

extern int
X509VerifyCb (
int            Status,
X509_STORE_CTX *Context
);

#endif /* CRYPTO_H */
