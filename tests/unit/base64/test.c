#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <setjmp.h>
#include <cmocka.h>
#include <getopt.h>

#include "base64.h"

#if defined(NTLM)
/* at v2.0 this was the enabling ifdef */
#define IS_BUILT

#elif defined(ENABLE_HTTP_PROXY) || defined(ENABLE_PKCS11)
/* at v2.1 this was the enabling ifdef */
#define IS_BUILT

#elif defined(ENABLE_HTTP_PROXY) || defined(ENABLE_PKCS11) || defined(ENABLE_CLIENT_CR)
/* at v2.2 this was the enabling ifdef
 * After v2.2_RC2 (at commit cf696), the implementation changed
 * _decode() has a third parameter, for buffer size.
 */
#define IS_BUILT

#elif defined(ENABLE_HTTP_PROXY) || defined(ENABLE_PKCS11) || defined(ENABLE_CLIENT_CR) || defined(MANAGMENT_EXTERNAL_KEY)
/* at v2.3 this was the enabling ifdef */
/* Also at v2.3 commit a4da1, the implementation changed.
 * The functions have an openvpn_ prefix now.
 */
#define IS_BUILT

#else
/* at v2.4 it was enabled unconditionally */
#define IS_BUILT

#endif

#ifdef IMPLEMENTATION_2_0
#define openvpn_base64_encode(src, len, dest)    base64_encode(src, len, dest)
#define openvpn_base64_decode(src, dest, buflen) base64_decode(src, dest)
#elif IMPLEMENTATION_2_2
#define openvpn_base64_encode(src, len, dest)    base64_encode(src, len, dest)
#define openvpn_base64_decode(src, dest, buflen) base64_decode(src, dest, buflen)
#endif


struct mystate {
  int has_data;
  char *plain_text;
  char *encoded_text;
  char decoded_text [128];
};

static int setup(void **state) {
     *state  = calloc(1, sizeof(struct mystate));
     return (*state == NULL);
}

static int teardown(void **state) {
  struct mystate *c = *state;

  free(c);
  return 0;
}

static void test_encode(void **state) {
  struct mystate *c = *state;

  assert_true (!c->has_data);
  assert_true (c->plain_text == NULL);
  assert_true (c->encoded_text == NULL);
  c->plain_text = "The quick fox...";

#ifdef IS_BUILT
  int encoded_len = openvpn_base64_encode(c->plain_text, strlen(c->plain_text), &c->encoded_text);

  msg(D_TEST_DEBUG, "_encode() outputs: '%s' (%d bytes), reports %d",
            c->encoded_text,
            strlen(c->encoded_text),
            encoded_len
            );
  assert_true (encoded_len == 24);
  assert_true (encoded_len == strlen(c->encoded_text));
  assert_true (c->encoded_text != NULL);
  assert_string_equal (c->encoded_text, "VGhlIHF1aWNrIGZveC4uLg==");
  c->has_data = 1;

  if (c->encoded_text != NULL)
    free (c->encoded_text);

#endif
}

static void test_decode(void **state) {
  struct mystate *c = *state;

  assert_true (c->has_data);
  assert_true (c->plain_text != NULL);
  assert_true (c->encoded_text != NULL);

#ifdef IS_BUILT
  /* there was an inherent bug here up to implementation 2.2:
   * If _decode() was buggy and output more
   * data than it should, it would overflow the decode buffer.
   * A more reasonable implementation would take a 3rd argument, size of output
   * buffer.
   * Then a test could be written to check that it doesn't overflow.
   *    assert_true (decoded_len < sizeof(c->decoded_text));
   * But with this implementation (pre 2.2), an overflow bug could be ruled out
   * by testing, only by code review.
   */
  int i;
  int decoded_len;
  c->encoded_text = "VGhlIHF1aWNrIGZveC4uLg==";

  for (i = 0; i < 5; i++, bp++)
    {
        decoded_len = openvpn_base64_decode(c->encoded_text, &c->decoded_text, sizeof(c->decoded_text));

        if (decoded_len >= 0 && decoded_len < sizeof (c->decoded_text) ) {
            c->decoded_text[decoded_len] = '\0';
            msg(D_TEST_DEBUG, "_decode() outputs: '%s' (%d bytes), reports %d",
                c->decoded_text,
                strlen(c->decoded_text),
                decoded_len);
          }
        else
          {
            msg(D_TEST_DEBUG, "_decode() returned unexpected %d", decoded_len);
          }

        assert_true (decoded_len == 16);
        assert_string_equal (c->decoded_text, c->plain_text);
    }
#endif
}

unsigned int verb = 0;

/* Convenience breakpoint variable. Set a conditional breakpoint on any line
 * in your debugger, on the condition that bp=={number}
 * In verbose mode, messages print the value of bp at the time they were called.
 * you can increment or change it anywhere state changes, and if you notice
 * something amiss, place a breakpoint at that state value. It's useful for
 * debugging the tests, stopping just before a section that is interesting to
 * step through.
 *
 * You can also place a breakpoint on the cmocka function _fail to stop as soon
 * as an assertion fails.
 */
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

int main(int argc, char **argv) {
    const struct CMUnitTest tests[] = {
#if defined(IS_BUILT)
        cmocka_unit_test(test_encode),
        cmocka_unit_test(test_decode),
#endif
    };

    int result;

#if !defined(IS_BUILT)
    dmsg(D_TEST_INFO, "This build configuration does not include base64 functions. Nothing to test");
#endif

    do_getopt (argc, argv);

#if defined(IS_BUILT)
    result = cmocka_run_group_tests_name("success_test", tests, setup, teardown);

    if (result == 255) /* Cmocka error, failed to test */
      return AUTOMAKE_TEST_HARD_ERROR;

    /* 0 = pass, 1 = fail */
    return !!result;
#else
#if defined (TEST_DOES_NOT_MAKE_SENSE_HERE)
    /* This is a test template. When creating another unit test from it,
     * some conditions may not make sense, eg, testing a Windows feature
     * when the test is built for Linux.
     * In that case, define TEST_DOES_NOT_MAKE_SENSE_HERE appropriately.
     *
     * In this particular case, base64, there is no such condition, this should
     * be tested everywhere.
     */
    return AUTOMAKE_TEST_SKIPPED; /* Tell automake this test is SKIPPED */
#else
    /* Hard error means the test did not execute (ie, did not test) the unit
     * (completely). Possible scenarios, if the defines are not setup to enable
     * the UUT to be built, or unexpectedly running out of memory, or segmentation
     * faults, or SIGINT.
     *
     * This test template only fails if the UUT is present but cannot be built
     * due to missing NTLM define (which is a requirement for base64 to be built)
     */
    return AUTOMAKE_TEST_HARD_ERROR;
#endif
#endif
}
