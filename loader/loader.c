/*
 * Loader Implementation
 *
 * 2018, Operating Systems
 */

#include "handler.h"

int so_init_loader(void)
{
	/* Initialize on-demand loader */
	pageSize = getpagesize();
	set_signal();

	return 0;
}

int so_execute(char *path, char *argv[])
{
	unsigned int no_pages;
	int i;

	/* Parse exec file */
	exec = so_parse_exec(path);
	if (!exec)
		return EXIT_FAILURE;

	/* Used to keep track of mapped pages
	 * of every segment
	 */
	for (i = 0; i < exec->segments_no; ++i) {
		no_pages = exec->segments[i].mem_size / pageSize + 1;
		exec->segments[i].data = calloc(no_pages, sizeof(char));
	}

	/* Filename needed in signal handler */
	memcpy(filename, path, strlen(path) + 1);

	/* Run */
	so_start_exec(exec, argv);

	/* Restore handler */
	restore_signal();

	return 0;
}
