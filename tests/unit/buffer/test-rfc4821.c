/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2020 Radu Hociung <radu.ovpndev@ohmi.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <setjmp.h>
#include <cmocka.h>

#include <getopt.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"
// #include "rfc4821.h"
#include "buffer.h"

FILE *
platform_fopen (const char *path, const char *mode)
{
  assert_true ( 0 && "Unexpected call to a placeholder function for "
                    "platform_fopen()" );
  return NULL;
}


static int
setup (void **state)
{
  *state = calloc (1, sizeof(struct buffer));
  *((struct buffer *) *state) = alloc_buf (100);

  return 0;
}

static int
teardown (void **state)
{
  struct buffer *buf = *state;
  free_buf (buf);
  free (buf);
  return 0;
}




static void
test_buffer_init (void **state)
{
  struct buffer *buf = *state;

  assert_true (buf != NULL && "Buffer allocation succeeds");

  assert_true (buf->ip_pmtudisc == BUF_PMTUDISC_DONT &&
      "Buffer initialization sets the buffer to IP_PMTUDISC_DONT");

}

static void
test_buffer_realloc (void **state)
{
  struct buffer *buf = *state;

  assert_true (buf != NULL && "Buffer allocation succeeds");
  assert_true (buf->capacity == 100 && "Buffer initial capacity should be 100");

  realloc_buf(buf, 200);

  assert_true (buf->capacity == 200 && "Buffer new capacity should be 200");
  uint8_t i;
  /* Write every byte so memory checker can do out of bounds checks. */
  for (i = 0 ; i < 200; i++, bp++)
    {
      assert_true(buf_write_u8(buf, i) && "Buffer write succeeds");
    }
}

/* Check that cmocka is sane.
 */
static void
test_plain_realloc (void **state)
{
  void *buf = calloc(1, 100);

  assert_true (buf != NULL && "Buffer allocation succeeds");

  memset (buf, 15, 100);

  buf = realloc (buf, 200);

  assert_true (buf != NULL && "Buffer reallocation succeeds");

  memset (buf, 17, 200);

  free (buf);
}

static void
test_buffer_fill_incompressible (void **state)
{
  struct buffer buf = alloc_buf (100);

  assert_true (buf.data != NULL && "Buffer allocation succeeds");

  assert_true (buf.ip_pmtudisc == BUF_PMTUDISC_DONT &&
      "Buffer initialization sets the buffer to BUF_PMTUDISC_DONT");

  buf_write_u32(&buf, 0xdeadbeef);

  srand (0);
  buf_fill_incompressible (&buf, 1000);

  assert_true (buf.capacity == 1000 && "Buffer capacity was increased to 1000");
  assert_true (buf.len == 1000 && "Buffer size increased to 1000");
  assert_true (buf.ip_pmtudisc == BUF_PMTUDISC_DO &&
      "Filling buffer with incompressible data also sets BUF_PMTUDISC_DO");

  bool success;
  uint32_t val;
  val = buf_read_u32 (&buf, &success);
  assert_true (success == true && "Reading initial word succeeds");
  assert_true (val == 0xdeadbeef && "First word is correct");

  int i;
  int v;
  srand (0);
  for (i = 0; i < 996; i++, bp++)
    {
      v = buf_read_u8(&buf);
      assert_true (v >= 0 && "Reading byte succeeds");
      assert_true (v = rand() && "Read byte is correct");
    }

  free_buf (&buf);
}

unsigned int verb = 0;
unsigned int bp = 0;

static void
do_getopt (int argc, char **argv)
{
  int c;
  while (1)
    {
      int option_index = 0;
      static struct option long_options[] = {
        {"verb", optional_argument, 0, 'v'},
        {0, 0, 0, 0}
      };

      c = getopt_long (argc, argv, "v::",
                       long_options, &option_index);
      if (c == -1)
        break;

      switch (c)
        {

        case 'v': if (optarg)
            verb = atoi (optarg);
          else
            verb++;
          break;
        case '?':
          exit (1);
          break;

        default:
          printf ("?? getopt returned character code 0%o ??\n", c);
        }
    }
}

int
main (int argc, char **argv)
{
  const struct CMUnitTest buffer_rfc4821_tests[] = {
    cmocka_unit_test_setup_teardown (test_buffer_init, setup, teardown),
    cmocka_unit_test                (test_plain_realloc),
    cmocka_unit_test                (test_buffer_fill_incompressible),
    cmocka_unit_test_setup_teardown (test_buffer_realloc, setup, teardown),
  };


  do_getopt (argc, argv);

  int result;
  result =  cmocka_run_group_tests_name ("buffer functionality used for rfc4821", buffer_rfc4821_tests, NULL, NULL);

  if (result == 255) /* Cmocka error, failed to test */
    return AUTOMAKE_TEST_HARD_ERROR;

  return !!result;
}
