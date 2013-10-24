
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
#include <time.h>
#include <unistd.h>
#include <Library/BaseCryptLib.h>

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

	struct stat sb;
	fstat(binfd, &sb);
	void *bin = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, binfd, 0);
	size_t bin_size = sb.st_size;

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

	WIN_CERTIFICATE_EFI_PKCS *efi_pkcs = NULL;

	if (context.SecDir->Size != 0) {
		efi_pkcs = ImageAddress(bin, bin_size,
				context.SecDir->VirtualAddress);
		if (!efi_pkcs) {
			fprintf(stderr, "signature is at invalid "
					"offset\n");
			exit(1);
		}
	}


	int found = 0;
	for (int i = 2; argv[i] != NULL; i++) {
		int fd = open(argv[i], O_RDONLY);
		if (fd < 0)
			err(1, "verify: %s", argv[i]);
		printf("adding cert from \"%s\"\n", argv[i]);

		uint8_t *cert;
		struct stat sb;

		fstat(fd, &sb);
		cert = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
		size_t cert_size = sb.st_size;
		
		rc = AuthenticodeVerify((UINT8 *)&efi_pkcs->CertData,
				efi_pkcs->Hdr.dwLength - sizeof(efi_pkcs->Hdr),
				cert, cert_size,
				sha256hash, 32);
		if (rc == 1) {
			found = 1;
			break;
		}

		munmap(cert, sb.st_size);
		close(fd);
	}

	if (!found) {
		fprintf(stderr, "verify failed!\n");
		exit(1);
	}
	printf("Image verifies correctly\n");

	return 0;
}

VOID
CopyMem(VOID *Dest, VOID *Src, UINTN len)
{
	memcpy(Dest, Src, len);
}

INTN
CompareMem(CONST VOID *Dest, CONST VOID *Src, UINTN len)
{
	return memcmp(Dest, Src, len);
}

VOID
ZeroMem(VOID *Buffer, UINTN Size)
{
	memset(Buffer, '\0', Size);
}

INTN
AsciiStrLen(CONST char *Str)
{
	return strlen(Str);
}

UINT32
WriteUnaligned32(UINT32 *Buffer, UINT32 Value)
{
	*Buffer = Value;
	return Value;
}
