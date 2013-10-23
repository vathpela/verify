#ifndef PE_H
#define PE_H

#include "wincert.h"
#include "PeImage.h"

extern int
get_pe_context(uint8_t *bin, size_t size,
	PE_COFF_LOADER_IMAGE_CONTEXT **context);

int
read_header(void *data, unsigned int datasize,
			      PE_COFF_LOADER_IMAGE_CONTEXT *context);

extern void *
ImageAddress (void *image, unsigned int size, unsigned int address);

extern int
generate_hash (char *data, unsigned int datasize_in,
		PE_COFF_LOADER_IMAGE_CONTEXT *context,
		UINT8 *sha256hash);
#endif /* PE_H */
