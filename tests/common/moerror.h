/* Tests   -- A test infrastructure for backwards-compatible testing
 *
 * Copyright (C) 2020 Radu Hociung <radu.tests@ohmi.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
/* Override regular error.h */

#ifndef ERROR_H
#define ERROR_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <setjmp.h>
#include <cmocka.h>

#include "errlevel.h"

#if !defined(NDEBUG)
#define my_expect_assert_failure(function_call, expected_assertion, explain) \
  { \
    const int result = setjmp(global_expect_assert_env); \
    global_expecting_assert = 1; \
    if (result) { \
      global_expecting_assert = 0; \
      if (strcmp(global_last_failed_assert, #expected_assertion)) {\
            print_error ("Wrong assertion failed: '%s', expected '%s' (%s)", \
                      global_last_failed_assert, #expected_assertion, explain); \
            _fail(__FILE__, __LINE__); \
      } \
    } else { \
      function_call ; \
      global_expecting_assert = 0; \
      print_error("Expected assert in %s\n", #function_call); \
      _fail(__FILE__, __LINE__); \
    } \
  }

#define ASSERT(x)  mock_assert(!!(x), #x, __FILE__, __LINE__)
#define static_assert(expr, diagnostic) assert_true( (expr) && (diagnostic))
#define IS_INITIALIZED(x) ((x)->is_init)
#else
#define ASSERT(x) do { (void)sizeof(x); } while(0)
#define static_assert(expr, diagnostic)
#define my_expect_assert_failure(function_call, expected_assertion, explain)
#define IS_INITIALIZED(x) 1
#endif

/* verbosity */
extern unsigned int verb;
/* Breakpoint id. A simple state identifier that enables conditional breakpoints
 * It is printed by msg(). To stop debugger at or before a particular printed
 * message, set a conditional bp on this variable */
extern unsigned int bp;

#define M_DEBUG_LEVEL     (0x0F)
#define M_FATAL           (1<<4)

#define M_NONFATAL        (1<<5)
#define M_WARN	          (0)
#define M_DEBUG           (0)
#define M_ERRNO           (0)

#ifdef ENABLE_CRYPTO_OPENSSL
#  define M_SSL             (0)
#endif

#define M_NOMUTE          (0)
#define M_NOPREFIX        (0)
#define M_USAGE_SMALL     (0)
#define M_MSG_VIRT_OUT    (0)
#define M_OPTERR          (0)
#define M_NOLF            (0)
#define M_NOIPREFIX       (0)

/* flag combinations which are frequently used */
#define M_ERR     (M_FATAL | M_ERRNO)
#define M_SSLERR  (M_FATAL | M_SSL)
#define M_USAGE   (M_USAGE_SMALL | M_NOPREFIX | M_OPTERR)
#define M_CLIENT  (M_MSG_VIRT_OUT | M_NOMUTE | M_NOIPREFIX)

#define D_TEST_INFO        (1)
#define D_TEST_DEBUG       (2)

#define LOGLEV(log_level, mute_level, other) (log_level)

#if defined(HAVE_CPP_VARARG_MACRO_ISO) && !defined(__LCLINT__)
# define HAVE_VARARG_MACROS
# define msg(flags, fmt, ...) do { if ( ((flags) & M_DEBUG_LEVEL) <= verb) { \
        printf("%-18s(%d)(bp==%u): ", #flags, (flags), bp); \
        printf(fmt, ##__VA_ARGS__); \
        printf("\n"); \
        } } while (0)
#elif defined(HAVE_CPP_VARARG_MACRO_GCC) && !defined(__LCLINT__)
# define HAVE_VARARG_MACROS
# define msg(flags, fmt, args...) do { if ( ((flags) & M_DEBUG_LEVEL) >= verb) \
        printf("%s(%d)(bp==%u): ", #flags, (flags), bp); \
        printf(fmt, args); \
        printf("\n"); \
        } while (0)
#else
# if !PEDANTIC
#  ifdef _MSC_VER
#   pragma message("this compiler appears to lack vararg macros. UUT messages will not be output.")
#  else
#   warning this compiler appears to lack vararg macros. UUT messages will not be output.
#  endif
# endif
# define msg do { } while (0)
#endif
#if ENABLE_DEBUG
#define dmsg msg
#else
#define dmsg(...)
#endif

#ifdef WIN32
# define openvpn_errno()             GetLastError()
# define openvpn_strerror(e, gc)     strerror_win32(e, gc)
  const char *strerror_win32 (DWORD errnum, struct gc_arena *gc);
#else
# define openvpn_errno()             errno
# define openvpn_strerror(x, gc)     strerror(x)
#endif

#include <stdbool.h>

static inline bool
check_debug_level(unsigned int level)
{
    return (level & M_DEBUG_LEVEL) <= verb;
}
#if !defined(HAVE_STDBOOL_H)
/* bool is hard defined in basic.h in 2.0, compile would fail if redefined
 * Later codebases rely on stdbool.h, which will not redefine if included
 * multiple times
 */
#undef bool
#endif

/** Convert fatal errors to nonfatal, don't touch other errors */
static inline unsigned int
nonfatal(const unsigned int err)
{
    return err & M_FATAL ? (err ^ M_FATAL) | M_NONFATAL : err;
}

#if false && !defined(NO_CMOCKA_MEMCHECK)
/** Memory leak and buffer over/underflow checking with cmocka */

/* It is disabled because both 1.1.0 and 1.1.1 have buggy test_realloc()
 * implementations.
 * TODO: Find out what's the minimum cmocka version that works with realloc.
 * Alternately, find another lightweight memory checking to use instead of
 * cmocka for package-builder use.
 */
/*
 * WARNING: cmocka may flag red-herrings.
 *
 * This naive implementation of memory checking triggers false positives, where
 * malloc is called from a library and free is called from UUT or test harness.
 * Consider:
 *
 * char *mycopy = strdup("False positive");
 * free(mycopy);
 *
 * In this case, libc allocates some memory when strdup is called. cmocka is
 * unaware of this malloc. When the UUT calls free(), which is diverted to
 * cmocka's test_free, cmocka detects a free without a corresponding malloc,
 * and throws an ambiguous error like "Could not run the test - check test fixtures"
 *
 * You can disable cmocka's memory checking by adding -DNO_CMOCKA_MEMCHECK to
 * CPPFLAGS, or better, find another workaround. Basic leak detection is very
 * useful for packagers, who will be linking the UUT with possibly broken
 * libraries. They may provide a workaround, or a bug report to the broken lib
 * maintainers. Disabling this MEMCHECK will help keep that bug hidden.
 */
#define malloc  test_malloc
#define calloc  test_calloc
#define realloc test_realloc
#define free	test_free
#endif

static inline void
out_of_memory(void)
{
    assert_true (0 && "Have enough of memory");
}

#ifdef WIN32
# define openvpn_errno_socket()      WSAGetLastError()
#else
# define openvpn_errno_socket()      errno
#endif

#define AUTOMAKE_TEST_SKIPPED 77
#define AUTOMAKE_TEST_HARD_ERROR 99

#endif