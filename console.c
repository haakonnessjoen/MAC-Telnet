/*
    Mac-Telnet - Connect to RouterOS routers via MAC address
    Copyright (C) 2010, Håkon Nessjøen <haakon.nessjoen@gmail.com>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/
#include <sys/ioctl.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <termios.h>
#include <unistd.h>

struct termios origTerm;

int rawTerm() {
	struct termios new;

	if (tcgetattr(STDIN_FILENO, &origTerm) < 0) {
		perror("tcgetattr");
		return -1;
	}

	memcpy(&new, &origTerm, sizeof(struct termios) );

	/* raw mode, from tcsetattr man page */
	new.c_iflag &= ~(IGNBRK|BRKINT|PARMRK|ISTRIP|INLCR|IGNCR|ICRNL|IXON);
	new.c_lflag &= ~(ECHO|ECHONL|ICANON|ISIG|IEXTEN);
	new.c_cflag &= ~(CSIZE|PARENB);
	new.c_cflag |= CS8;

	if (tcsetattr(STDIN_FILENO, TCSANOW, &new) < 0) {
		perror("tcsetattr");
		return -1;
	}
	return 0;
}

int resetTerm() {
	if (tcsetattr(STDIN_FILENO, TCSANOW, &origTerm) < 0) {
		perror("tcsetattr");
		return -1;
	}
	return 0;
}

int getTerminalSize(unsigned short *width, unsigned short *height) {
	struct winsize ws;

	if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) != 0) {
		perror("TIOCGWINSZ");
		return -1;
	}

	*width = ws.ws_col;
	*height = ws.ws_row;

	return 1;
}
