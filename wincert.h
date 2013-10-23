#ifndef _WINCERT_H
#define _WINCERT_H 1

#define WIN_CERT_TYPE_PKCS_SIGNED_DATA 0x0002
#define WIN_CERT_TYPE_EFI_PKCS115      0x0EF0
#define WIN_CERT_TYPE_EFI_GUID         0x0EF1

typedef struct {
	uint32_t dwLength;
	uint16_t wRevision;
	uint16_t wCertificateType;
} WIN_CERTIFICATE;

#define EFI_CERT_X509_GUID \
  {0xa5c059a1,0x94e4,0x4aa7, {0x87,0xb5,0xab,0x15,0x5c,0x2b,0xf0,0x72}}

#define EFI_CERT_TYPE_RSA2048_SHA256_GUID \
  {0xa7717414,0xc616,0x4977, {0x94,0x20,0x84,0x47,0x12,0xa7,0x35,0xbf}}

#define EFI_CERT_TYPE_PKCS7_GUID \
  EFI_GUID(0x4aafd29d,0x68df,0x49ee,0x8aa9,0x34,0x7d,0x37,0x56,0x65,0xa7)

typedef struct {
	efi_guid_t HashType;
	uint8_t PublicKey[256];
	uint8_t Signature[256];
} EFI_CERT_BLOCK_RSA_2048_SHA256;

typedef struct {
	WIN_CERTIFICATE Hdr;
	efi_guid_t CertType;
	UINT8 CertData[1];
} WIN_CERTIFICATE_EFI_GUID;

typedef struct {
	WIN_CERTIFICATE Hdr;
	UINT8 CertData[1];
} WIN_CERTIFICATE_EFI_PKCS;

typedef struct {
	uint64_t MonotonicCount;
	WIN_CERTIFICATE_EFI_GUID AuthInfo;
} EFI_VARIABLE_AUTHENTICATION;

typedef struct {
	EFI_TIME TimeStamp;
	WIN_CERTIFICATE_EFI_GUID AuthInfo;
} EFI_VARIABLE_AUTHENTICATION_2;

typedef struct {
	EFI_GUID SignatureOwner;
	// UINT8 SignatureData[1];
} EFI_SIGNATURE_DATA;

typedef struct {
	EFI_GUID SignatureType;
	UINT32 SignatureListSize;
	UINT32 SignatureHeaderSize;
	UINT32 SignatureSize;
	// UINT8 SignatureHeader[SignatureHeaderSize];
	// EFI_SIGNATURE_DATA Signatures[][SignatureSize];
} EFI_SIGNATURE_LIST;

#endif /* _WINCERT_H */
