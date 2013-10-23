
#include <fcntl.h>
#include <err.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

struct _cert_list_entry;
typedef struct _cert_list_entry {
	uint8_t *cert;
	size_t size;
	struct _cert_list_entry *next;
} cert_list_entry;

static void
add_cert(cert_list_entry **db, int fd)
{
	struct stat sb;
	fstat(fd, &sb);

	void *addr = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (!addr)
		err(1, "verify");

	void *cert = malloc(sb.st_size);
	if (!cert)
		err(1, "verify");

	memcpy(cert, addr, sb.st_size);
	munmap(addr, sb.st_size);

	cert_list_entry *cle = malloc(sizeof (*cle));
	if (!cle)
		err(1, "verify");

	cle->cert = cert;
	cle->size = sb.st_size;
	cle->next = *db;
	*db = cle;
}

int
main(int argc, char *argv[])
{
	if (argc < 3) {
		fprintf(stderr, "usage: verify foo.efi cert0 [... certN]\n");
		exit(1);
	}

	int binfd = open(argv[1], O_RDONLY);
	if (binfd < 0)
		err(1, "verify: %s", argv[1]);

	cert_list_entry *certdb = NULL;
	for (int i = 2; argv[i] != NULL; i++) {
		int certfd = open(argv[2], O_RDONLY);
		if (certfd < 0)
			err(1, "verify: %s", argv[i]);
		add_cert(&certdb, certfd);
		close(certfd);
	}

	struct stat binsb;
	fstat(binfd, &binsb);
	void *bin = mmap(NULL, binsb.st_size, PROT_READ, MAP_PRIVATE, binfd, 0);

	

	return 0;
}
