#include <sys/ioctl.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>

int getTerminalSize(unsigned short *width, unsigned short *height) {
	struct winsize ws;

	if (ioctl(0,TIOCGWINSZ,&ws) != 0) {
		fprintf(stderr,"TIOCGWINSZ:%s\n",strerror(errno));
		return -1;
	}

	*width = ws.ws_col;
	*height = ws.ws_row;

	printf("Console width: %d, height: %d\n", *width, *height);

	return 1;
}
