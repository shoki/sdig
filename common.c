/* common.c - common useful functions

   Copyright (C) 2000  Russell Kroll <rkroll@exploits.org>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
*/

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <stdarg.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>

#include "common.h"

	int	debuglevel = 0;

/* debug levels:
 *
 * 2 - function entry messages
 * 3 - function status messages
 * 4 - snmpget calls
 * 5 - popen calls
 * 6 - snmpget results, parsing details
 * 7 - popen reads
 */

void debug(int level, const char *format, ...)
{
	va_list	args;

	if (debuglevel < level)
		return;

	va_start(args, format);
	vprintf(format, args);
	va_end(args);
}

void fatal(const char *fmt, ...)
{
	va_list va;
	char	msg[LARGEBUF];

	va_start(va, fmt);
	vsnprintf(msg, sizeof(msg), fmt, va);
	va_end(va);

	fprintf(stderr, "Fatal error: %s\n", msg);
        exit(1);
}


/* split up buf into a number of substrings, returning pointers in arg */
int parseconf(const char *fn, int ln, char *buf, char **arg, int numargs)
{
	char	*ptr, *ws;
	int	i, buflen, an, state;

	an = state = 0;
	ws = NULL;

	buflen = strlen (buf);
	ptr = buf;

	/* yes, it's a state machine! be afraid! */

	for (i = 0; i < buflen; i++) {
		switch (state) {
			case 0:		/* scan */
				if (*ptr == '"') {
					ws = ptr + 1; 	/* start after quote */
					state = 1;	/* goto quotecollect */
					break;
				}

				if (isspace(*ptr))
					break;		/* loop */

				if (*ptr == '\\') {	/* literal as start */
					if (i == (buflen - 1)) {
						fprintf(stderr, "%s:%d:"
						"\\ at end of line!", 
						fn, ln);
						return 0;	/* failure */
					}

					ws = ptr;

					/* shift string to the left */
					memmove(ptr, ptr+1, buflen-i);

					/* fix length */
					buflen--;

					state = 2;	/* goto collect */
				}

				if (!isspace(*ptr)) {
					ws = ptr;
					state = 2;	/* goto collect */
					break;
				}
			
				break;

			case 1:		/* quotecollect */
				if (*ptr == '"')
					state = 3;	/* goto save */

				if (*ptr == '\\') {	/* literal handling */
					if (i == (buflen - 1)) {
						fprintf(stderr, "%s:%d:"
						"\\ at end of line!", 
						fn, ln);
						return 0;	/* failure */
					}

					/* shift string to the left */
					memmove(ptr, ptr+1, buflen-i);

					/* fix length */
					buflen--;
				}

				break;			/* loop */

			case 2:		/* collect */
				if (*ptr == '\\') {	/* literal handling */
					if (i == (buflen - 1)) {
						fprintf(stderr, "%s:%d:"
						"\\ at end of line!", 
						fn, ln);
						return 0;	/* failure */
					}

					/* shift string to the left */
					memmove(ptr, ptr+1, buflen-i);

					/* fix length */
					buflen--;
					break;		/* loop */
				}

				if (!isspace(*ptr))
					break;		/* loop */

				state = 3;		/* goto save */
		}

		if (state == 3) {		/* save */
			if (an < numargs)
				arg[an++] = ws;
			*ptr = '\0';
			ws = NULL;
			state = 0;
		}

		ptr++;
	}

	if (state == 1) {	/* end-of-string in state 1 == missing quote */
		fprintf(stderr, "%s:%d: Unbalanced \" in line", fn, ln);
		return 0;	/* FAILED */
	}

	if (state == 2) {	/* catch last word when exiting from collect */
		*ptr = '\0';
		if (an < numargs)
			arg[an++] = ws;
	}

	/* zap any leftover pointers */
	for (i = an; i < numargs; i++)
		arg[i] = NULL;

	/* safety catch: don't allow all nulls back as 'success' */
	if (arg[0] == NULL)
		return 0;	/* FAILED (don't parse this) */

	return 1;	/* success */
}

int snprintfcat(char *dst, size_t size, const char *fmt, ...)
{
	va_list ap;
	int len = strlen(dst);
	int ret;

	size--;

	va_start(ap, fmt);
	ret = vsnprintf(dst + len, size - len, fmt, ap);
	va_end(ap);

	dst[size] = '\0';
	return len + ret;
}

static const char *oom_msg = "Out of memory";

void *xmalloc(size_t size)
{
	void *p = malloc(size);

	if (p == NULL)
		fatal("%s", oom_msg);
	return p;
}

char *xstrdup(const char *string)
{
	char *p = strdup(string);

	if (p == NULL)
		fatal("%s", oom_msg);
	return p;
}

