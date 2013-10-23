#ifndef PE_H
#define PE_H

#include "wincert.h"

extern int
get_data_dictionary(uint8_t *bin, size_t size,
		    WIN_CERTIFICATE_EFI_PKCS **cert, size_t *cert_size);

#endif /* PE_H */
