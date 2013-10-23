
#include <efi.h>
#include <efivar.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

#include "crypto.h"
#include "PeImage.h"
#include "pe.h"
#include "wincert.h"

void *
ImageAddress (void *image, unsigned int size, unsigned int address)
{
	if (address > size)
		return NULL;

	return image + address;
}

/*
 * Read the binary header and grab appropriate information from it
 */
int
read_header(void *data, unsigned int datasize,
			      PE_COFF_LOADER_IMAGE_CONTEXT *context)
{
	EFI_IMAGE_DOS_HEADER *DosHdr = data;
	EFI_IMAGE_OPTIONAL_HEADER_UNION *PEHdr = data;
	unsigned long HeaderWithoutDataDir, SectionHeaderOffset;

	if (datasize < sizeof(EFI_IMAGE_DOS_HEADER)) {
		fprintf(stderr, "Invalid image\n");
		errno = EINVAL;
		return -1;
	}

	if (DosHdr->e_magic == EFI_IMAGE_DOS_SIGNATURE)
		PEHdr = (EFI_IMAGE_OPTIONAL_HEADER_UNION *)((char *)data + DosHdr->e_lfanew);

	if (EFI_IMAGE_NUMBER_OF_DIRECTORY_ENTRIES
			< PEHdr->Pe32Plus.OptionalHeader.NumberOfRvaAndSizes) {
		fprintf(stderr, "Image header too small\n");
		errno = EINVAL;
		return -1;
	}

	HeaderWithoutDataDir = sizeof (EFI_IMAGE_OPTIONAL_HEADER64)
			- sizeof (EFI_IMAGE_DATA_DIRECTORY) * EFI_IMAGE_NUMBER_OF_DIRECTORY_ENTRIES;
	if (((UINT32)PEHdr->Pe32Plus.FileHeader.SizeOfOptionalHeader - HeaderWithoutDataDir) !=
			PEHdr->Pe32Plus.OptionalHeader.NumberOfRvaAndSizes
				* sizeof (EFI_IMAGE_DATA_DIRECTORY)) {
		fprintf(stderr, "Image header overflows data directory\n");
		errno = EINVAL;
		return -1;
	}

	SectionHeaderOffset = DosHdr->e_lfanew
				+ sizeof (UINT32)
				+ sizeof (EFI_IMAGE_FILE_HEADER)
				+ PEHdr->Pe32Plus.FileHeader.SizeOfOptionalHeader;
	if ((PEHdr->Pe32Plus.OptionalHeader.SizeOfImage - SectionHeaderOffset) / EFI_IMAGE_SIZEOF_SECTION_HEADER
			<= PEHdr->Pe32Plus.FileHeader.NumberOfSections) {
		fprintf(stderr, "Image sections overflow image size\n");
		errno = EINVAL;
		return -1;
	}

	if ((PEHdr->Pe32Plus.OptionalHeader.SizeOfHeaders - SectionHeaderOffset) / EFI_IMAGE_SIZEOF_SECTION_HEADER
			< (UINT32)PEHdr->Pe32Plus.FileHeader.NumberOfSections) {
		fprintf(stderr, "Image sections overflow section headers\n");
		errno = EINVAL;
		return -1;
	}

	if ((((UINT8 *)PEHdr - (UINT8 *)data) + sizeof(EFI_IMAGE_OPTIONAL_HEADER_UNION)) > datasize) {
		fprintf(stderr, "Invalid image\n");
		errno = EINVAL;
		return -1;
	}

	if (PEHdr->Te.Signature != EFI_IMAGE_NT_SIGNATURE) {
		fprintf(stderr, "Unsupported image type\n");
		errno = EINVAL;
		return -1;
	}

	if (PEHdr->Pe32.FileHeader.Characteristics & EFI_IMAGE_FILE_RELOCS_STRIPPED) {
		fprintf(stderr, "Unsupported image - Relocations have been stripped\n");
		errno = EINVAL;
		return -1;
	}

	if (PEHdr->Pe32.OptionalHeader.Magic != EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		fprintf(stderr, "Only 64-bit images supported\n");
		errno = EINVAL;
		return -1;
	}

	context->PEHdr = PEHdr;
	context->ImageAddress = PEHdr->Pe32Plus.OptionalHeader.ImageBase;
	context->ImageSize = (UINT64)PEHdr->Pe32Plus.OptionalHeader.SizeOfImage;
	context->SizeOfHeaders = PEHdr->Pe32Plus.OptionalHeader.SizeOfHeaders;
	context->EntryPoint = PEHdr->Pe32Plus.OptionalHeader.AddressOfEntryPoint;
	context->RelocDir = &PEHdr->Pe32Plus.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC];
	context->NumberOfRvaAndSizes = PEHdr->Pe32Plus.OptionalHeader.NumberOfRvaAndSizes;
	context->NumberOfSections = PEHdr->Pe32.FileHeader.NumberOfSections;
	context->FirstSection = (EFI_IMAGE_SECTION_HEADER *)((char *)PEHdr + PEHdr->Pe32.FileHeader.SizeOfOptionalHeader + sizeof(UINT32) + sizeof(EFI_IMAGE_FILE_HEADER));
	context->SecDir = (EFI_IMAGE_DATA_DIRECTORY *) &PEHdr->Pe32Plus.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY];

	if (context->ImageSize < context->SizeOfHeaders) {
		fprintf(stderr, "Invalid image\n");
		errno = EINVAL;
		return -1;
	}

	if ((unsigned long)((UINT8 *)context->SecDir - (UINT8 *)data) >
	    (datasize - sizeof(EFI_IMAGE_DATA_DIRECTORY))) {
		fprintf(stderr, "Invalid image\n");
		errno = EINVAL;
		return -1;
	}

	if (context->SecDir->VirtualAddress >= datasize) {
		fprintf(stderr, "Malformed security header\n");
		errno = EINVAL;
		return -1;
	}
	return 0;
}

#if 0
#define dprintf(fmt, ...)
#else
#define dprintf(fmt, args...) printf(fmt, ## args)
#endif

int
generate_hash (char *data, unsigned int datasize,
		PE_COFF_LOADER_IMAGE_CONTEXT *context,
		UINT8 *sha256hash)
{
	unsigned int sha256ctxsize;
	unsigned int size = datasize;
	SHA256_CTX *sha256ctx = NULL;
	char *hashbase;
	unsigned int hashsize;
	unsigned int SumOfBytesHashed, SumOfSectionBytes;
	unsigned int index, pos;
	EFI_IMAGE_SECTION_HEADER  *Section;
	EFI_IMAGE_SECTION_HEADER  *SectionHeader = NULL;
	EFI_IMAGE_SECTION_HEADER  *SectionCache;
	int status = 0;

	sha256ctxsize = sizeof(*sha256ctx);
	sha256ctx = malloc(sha256ctxsize);

	if (!sha256ctx) {
		fprintf(stderr,"Unable to allocate memory for hash context\n");
		return -1;
	}

	if (!SHA256_Init(sha256ctx)) {
		fprintf(stderr,"Unable to initialise hash\n");
		status = -1;
		goto done;
	}

	/* Hash start to checksum */
	hashbase = data;
	hashsize = (char *)&context->PEHdr->Pe32.OptionalHeader.CheckSum -
		hashbase;

	if (!(SHA256_Update(sha256ctx, hashbase, hashsize))) {
		fprintf(stderr,"Unable to generate hash\n");
		status = -1;
		goto done;
	}

	/* Hash post-checksum to start of certificate table */
	hashbase = (char *)&context->PEHdr->Pe32.OptionalHeader.CheckSum +
		sizeof (int);
	hashsize = (char *)context->SecDir - hashbase;

	if (!(SHA256_Update(sha256ctx, hashbase, hashsize))) {
		fprintf(stderr,"Unable to generate hash\n");
		status = -1;
		goto done;
	}

	/* Hash end of certificate table to end of image header */
	hashbase = (char *) &context->PEHdr->Pe32Plus.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY + 1];
	hashsize = context->PEHdr->Pe32Plus.OptionalHeader.SizeOfHeaders -
		(int) ((char *) (&context->PEHdr->Pe32Plus.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY + 1]) - data);

	if (!(SHA256_Update(sha256ctx, hashbase, hashsize))) {
		fprintf(stderr,"Unable to generate hash\n");
		status = -1;
		goto done;
	}

	/* Sort sections */
	SumOfBytesHashed = context->PEHdr->Pe32Plus.OptionalHeader.SizeOfHeaders;

	Section = (EFI_IMAGE_SECTION_HEADER *) (
		(char *)context->PEHdr + sizeof (UINT32) +
		sizeof (EFI_IMAGE_FILE_HEADER) +
		context->PEHdr->Pe32.FileHeader.SizeOfOptionalHeader
		);

	SectionCache = Section;

	for (index = 0, SumOfSectionBytes = 0; index < context->PEHdr->Pe32.FileHeader.NumberOfSections; index++, SectionCache++) {
		SumOfSectionBytes += SectionCache->SizeOfRawData;
	}

	if (SumOfSectionBytes >= datasize) {
		fprintf(stderr,"Malformed binary: %x %x\n", SumOfSectionBytes, size);
		status = -1;
		goto done;
	}

	SectionHeader = (EFI_IMAGE_SECTION_HEADER *) calloc(sizeof (EFI_IMAGE_SECTION_HEADER), context->PEHdr->Pe32.FileHeader.NumberOfSections);
	if (SectionHeader == NULL) {
		fprintf(stderr,"Unable to allocate section header\n");
		status = -1;
		goto done;
	}

	/* Sort the section headers */
	for (index = 0; index < context->PEHdr->Pe32.FileHeader.NumberOfSections; index++) {
		pos = index;
		while ((pos > 0) && (Section->PointerToRawData < SectionHeader[pos - 1].PointerToRawData)) {
			memcpy(&SectionHeader[pos], &SectionHeader[pos - 1], sizeof (EFI_IMAGE_SECTION_HEADER));
			pos--;
		}
		memcpy(&SectionHeader[pos], Section, sizeof (EFI_IMAGE_SECTION_HEADER));
		Section += 1;
	}

	/* Hash the sections */
	for (index = 0; index < context->PEHdr->Pe32.FileHeader.NumberOfSections; index++) {
		Section = &SectionHeader[index];
		if (Section->SizeOfRawData == 0) {
			continue;
		}
		hashbase  = ImageAddress(data, size, Section->PointerToRawData);
		hashsize  = (unsigned int) Section->SizeOfRawData;

		if (!hashbase) {
			fprintf(stderr,"Malformed section header\n");
			status = -1;
			goto done;
		}

		if (!(SHA256_Update(sha256ctx, hashbase, hashsize))) {
			fprintf(stderr,"Unable to generate hash\n");
			status = -1;
			goto done;
		}
		SumOfBytesHashed += Section->SizeOfRawData;
	}

	/* Hash all remaining data */
	if (size > SumOfBytesHashed) {
		hashbase = data + SumOfBytesHashed;
		hashsize = (unsigned int)(
			size -
			context->PEHdr->Pe32Plus.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY].Size -
			SumOfBytesHashed);

		if (!(SHA256_Update(sha256ctx, hashbase, hashsize))) {
			fprintf(stderr,"Unable to generate hash\n");
			status = -1;
			goto done;
		}
	}

	if (!(SHA256_Final(sha256hash, sha256ctx))) {
		fprintf(stderr,"Unable to finalise hash\n");
		status = -1;
		goto done;
	}

done:
	if (SectionHeader)
		free(SectionHeader);
	if (sha256ctx)
		free(sha256ctx);

	return status;
}


int
get_pe_context(uint8_t *bin, size_t size,
	PE_COFF_LOADER_IMAGE_CONTEXT **context)
{
	return -1;
}
