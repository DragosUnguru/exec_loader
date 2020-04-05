#include <signal.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/stat.h>

#include "exec_parser.h"

/* useful macro for handling error codes */
#define DIE(assertion, call_description)				\
	do {								\
		if (assertion) {					\
			fprintf(stderr, "(%s, %d): ",			\
					__FILE__, __LINE__);		\
			perror(call_description);			\
			exit(EXIT_FAILURE);				\
		}							\
	} while (0)

#define MIN(a, b) ((a < b) ? a : b)
#define MAX(a, b) ((a < b) ? b : a)

static so_exec_t *exec;
static int pageSize;
static struct sigaction old_action;
static char filename[64];

static so_seg_t get_addr_segment(const void *address)
{
	so_seg_t segment;
	uintptr_t addr;
	int i;

	addr = (uintptr_t) address;
	for (i = 0; i < exec->segments_no; ++i) {
		segment = exec->segments[i];

		if (addr >= segment.vaddr && addr < segment.vaddr + segment.mem_size)
			return segment;
	}

	/* Invalid memory access.
	 * Address isn't in any segment
	 */
	segment.vaddr = UINTPTR_MAX;
	return segment;
}

static void segv_handler(int signum, siginfo_t *info, void *context)
{
	char *addr;
	char *src, *dst;
	char *data;
	int page, rc, fdin;
	so_seg_t segment;
	int mappingSize, fileSize;
	void *pageAddress;

	/* Check if the signal is SIGSEGV */
	if (signum != SIGSEGV) {
		old_action.sa_sigaction(signum, info, context);
		return;
	}

	/* Obtain the memory location
	 * which caused the page fault
	 */
	addr = (char *) info->si_addr;

	/* Search the segment of accessed address */
	segment = get_addr_segment(info->si_addr);

	/* Segment not found. Invalid address accessed */
	if (segment.vaddr == UINTPTR_MAX) {
		old_action.sa_sigaction(signum, info, context);
		return;
	}

	/* Obtain the page which caused the page fault */
	page = ((uintptr_t) addr - segment.vaddr) / pageSize;

	/* Page already mapped. Invalid access */
	data = (char *) segment.data;
	if (data[page]) {
		old_action.sa_sigaction(signum, info, context);
		return;
	}

	/* Map page */
	data[page] = 1;

	/* Compute page starting address */
	pageAddress = (void *) (ALIGN_DOWN((uintptr_t) addr, pageSize));

	/* Effective data to be written from file */
	mappingSize = segment.file_size -
		(int) ((uintptr_t) pageAddress - segment.vaddr);
	mappingSize = MIN(pageSize, MAX(0, mappingSize));

	fdin = open(filename, O_RDONLY);
	DIE(fdin == -1, "open file");

	/* Get file size */
	fileSize = lseek(fdin, 0, SEEK_END);
	DIE(fileSize == -1, "lseek");

	/* Map a page-sized chunk of file,
	 * starting from offset
	 */
	src = mmap(0, fileSize, PROT_READ, MAP_SHARED, fdin,
			segment.offset + page * pageSize);
	DIE(src == (char *) -1, "mmap");

	/* Map page in memory.
	 * MAP_PRIVATE zeroizes page.
	 * Give write permissions so we can write data to
	 * it and read for .bss and
	 * manage demanded permissions later
	 */
	dst = mmap(pageAddress, pageSize, PROT_WRITE | PROT_READ,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	DIE(dst == (char *) -1, "mmap");

	/* Copy data */
	memcpy(dst, src, mappingSize);

	/* Manage permissions */
	mprotect(pageAddress, mappingSize, segment.perm);

	/* Clean up */
	rc = munmap(src, pageSize);
	DIE(rc == -1, "munmap");

	rc = close(fdin);
	DIE(rc == -1, "close file");
}

static void set_signal(void)
{
	struct sigaction action;
	int rc;

	action.sa_sigaction = segv_handler;
	sigemptyset(&action.sa_mask);
	sigaddset(&action.sa_mask, SIGSEGV);
	action.sa_flags = SA_SIGINFO;

	rc = sigaction(SIGSEGV, &action, &old_action);
	DIE(rc == -1, "sigaction");
}

static void restore_signal(void)
{
	struct sigaction action;
	int rc;

	action.sa_sigaction = old_action.sa_sigaction;
	sigemptyset(&action.sa_mask);
	sigaddset(&action.sa_mask, SIGSEGV);
	action.sa_flags = SA_SIGINFO;

	rc = sigaction(SIGSEGV, &action, NULL);
	DIE(rc == -1, "sigaction");
}
