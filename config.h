#ifndef _CONFIG_H
#define _CONFIG_H 1

#define DEBUG 0

#if defined(__APPLE__) && defined(__MACH__)
#define PLATFORM_NAME "Mac OS X"

#elif defined(__FreeBSD__)
#define PLATFORM_NAME "FreeBSD"

#elif defined(__NetBSD__)
#define PLATFORM_NAME "NetBSD"

#elif defined(__OpenBSD__)
#define PLATFORM_NAME "OpenBSD"

#elif defined(__MINT__)
#define PLATFORM_NAME "FreeMiNT"

#elif defined(__bsdi__)
#define PLATFORM_NAME "BSD/OS"

#elif defined(linux) || defined(__linux__)
#define PLATFORM_NAME "Linux"

#elif defined(sun)
#define PLATFORM_NAME "Solaris"

#elif defined(__hpux)
#define PLATFORM_NAME "HPUX"

#elif defined(__riscos__)
#define PLATFORM_NAME "RISC OS"

#else
#define PLATFORM_NAME "Unknown"

#endif

#endif
