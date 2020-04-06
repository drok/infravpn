/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2016-2018 Fox Crypto B.V. <openvpn@fox-it.com>
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
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <setjmp.h>
#include <cmocka.h>
#include <getopt.h>

#include "syshead.h"

#include "buffer.h"

FILE *
platform_fopen (const char *path, const char *mode)
{
  assert_true ( 0 && "Unexpected call to a placeholder function for "
                    "platform_fopen()" );
  return NULL;
}

/* Backwards compatibility tweaks (#if .. #elif ladder in descending order)
 * Allow some new tests to run against obsoleted interfaces.
 * Ie, how to run 2.new tests on 2.old libraries?
 */
#if defined(IMPLEMENTATION_2_4)
    /* buffer_list_aggregate() introduced at 2.2, assumes separator = ""
     * replaced @ 2.4, this function was added, which uses the non-empty separator:
     *
     * buffer_list_aggregate_separator(struct buffer_list *bl,
     *                                 const size_t max_len,
     *                                 const char *sep);
     */
    #define testsep ","

#elif defined(IMPLEMENTATION_2_2)
    /* 2.2 and 2.3 don't support separator for buffer_list_aggregate, so use
     * the empty string instead, to get some value out of the existing tests
     * which were first written for the 2.4 version with custom separator
     * support.
     *
     * The signature at 2.2 is:
     * buffer_list_aggregate (struct buffer_list *bl, const size_t max)
     *
     *
     */
    #define testsep ""

    /* Define a compatibility function, so tests that don't specifically test
     * non-empty separators can run.
     */
    #define buffer_list_aggregate_separator(bl,max,sep) do { \
      assert_true ( !strcmp(sep, "") &&  \
        "IMPLEMENTATION_2_2 does not support aggregate separator. " \
        "The test is broken."); \
                buffer_list_aggregate(bl,max); \
        } while (0)

#endif

/* Forward compatibility tweaks (#if .. #elif ladder in ascending order)
 * Later revision implementations normally assume all lower revisions are still
 * implemented, ie, new functions are added, but not removed.
 * If in some future branch, 2_0 is completely removed, the new assumption
 * in that branch will be that the API is 2.2, while all the other branches
 * can still use the 2.0 API.
 *
 * Instead of thinking about fwd compatibility, it may be easier to update the
 * test to the latest version, and update the backward-compatibility tweak
 * section.
 */
#if defined(IMPLEMENTATION_2_0)
#elif defined(IMPLEMENTATION_2_2)
/* How to run 2.old code on 2.new library?
 */
#elif defined(IMPLEMENTATION_2_3)
#elif defined(IMPLEMENTATION_2_4)
#elif defined(IMPLEMENTATION_2_5)
#endif


#if defined(IMPLEMENTATION_2_4)
/* test functionality that did not exist before 2.4 */
static void
test_buffer_strprefix(void **state)
{
    assert_true(strprefix("123456", "123456"));
    assert_true(strprefix("123456", "123"));
    assert_true(strprefix("123456", ""));
    assert_false(strprefix("123456", "456"));
    assert_false(strprefix("12", "123"));
}
#endif

#if defined(IMPLEMENTATION_2_3)
/* Support the 2.3 signature change:
 * buffer_list_push(struct buffer_list *ol, const char *str)
 */
#define teststr_type char *
#elif defined(IMPLEMENTATION_2_2)
/* Buffer list implementation was added at 2.2 with this signature:
 * buffer_list_push (struct buffer_list *ol, const unsigned char *str)
 */
#define teststr_type unsigned char *
#endif

#if defined(IMPLEMENTATION_2_2)
#if defined(IMPLEMENTATION_2_4)
#else
#endif
#define testnosep ""
#define teststr1 "one"
#define teststr2 "two"
#define teststr3 "three"
#define teststr4 "four"
#endif

#define assert_buf_equals_str(buf, str) \
    assert_int_equal(BLEN(buf), strlen((char *)str)); \
    assert_memory_equal(BPTR(buf), str, BLEN(buf));

#if defined(IMPLEMENTATION_2_2)
/* test functionality that did not exist before 2.2 */

struct test_buffer_list_aggregate_ctx {
    struct buffer_list *empty;
    struct buffer_list *one_two_three;
    struct buffer_list *zero_length_strings;
    struct buffer_list *empty_buffers;
};

static int test_buffer_list_setup(void **state)
{
    struct test_buffer_list_aggregate_ctx *ctx  = calloc(1, sizeof(*ctx));
    ctx->empty = buffer_list_new(0);

    ctx->one_two_three = buffer_list_new(3);
    buffer_list_push(ctx->one_two_three, (teststr_type) teststr1);
    buffer_list_push(ctx->one_two_three, (teststr_type) teststr2);
    buffer_list_push(ctx->one_two_three, (teststr_type) teststr3);

    ctx->zero_length_strings = buffer_list_new(2);
    buffer_list_push(ctx->zero_length_strings, (teststr_type) "");
    buffer_list_push(ctx->zero_length_strings, (teststr_type) "");

    ctx->empty_buffers = buffer_list_new(2);
    uint8_t data = 0;
    buffer_list_push_data(ctx->empty_buffers, &data, 0);
    buffer_list_push_data(ctx->empty_buffers, &data, 0);

    *state = ctx;
    return 0;
}

static int test_buffer_list_teardown(void **state)
{
    struct test_buffer_list_aggregate_ctx *ctx = *state;

    buffer_list_free(ctx->empty);
    buffer_list_free(ctx->one_two_three);
    buffer_list_free(ctx->zero_length_strings);
    buffer_list_free(ctx->empty_buffers);
    free(ctx);
    return 0;
}

static void
test_buffer_list_full(void **state)
{
    struct test_buffer_list_aggregate_ctx *ctx = *state;

    /* list full */
    assert_int_equal(ctx->one_two_three->size, 3);
    buffer_list_push(ctx->one_two_three, (teststr_type) teststr4);
    assert_int_equal(ctx->one_two_three->size, 3);
}

static void
test_buffer_list_aggregate_separator_empty(void **state)
{
    struct test_buffer_list_aggregate_ctx *ctx = *state;

    /* aggregating an empty buffer list results in an empty buffer list */
    buffer_list_aggregate_separator(ctx->empty, 3, testsep);
    assert_null(ctx->empty->head);
}

static void
test_buffer_list_aggregate_separator_noop(void **state)
{
    struct test_buffer_list_aggregate_ctx *ctx = *state;

    /* With a max length of 2, no aggregation should take place */
    buffer_list_aggregate_separator(ctx->one_two_three, 2, testsep);
    assert_int_equal(ctx->one_two_three->size, 3);
    struct buffer *buf = buffer_list_peek(ctx->one_two_three);
    assert_buf_equals_str(buf, teststr1);
}

static void
test_buffer_list_aggregate_separator_two(void **state)
{
    struct test_buffer_list_aggregate_ctx *ctx = *state;
    const char *expected = teststr1 testsep teststr2 testsep;

    /* Aggregate the first two elements
     * (add 1 to max_len to test if "three" is not sneaked in too)
     */
    buffer_list_aggregate_separator(ctx->one_two_three, strlen(expected) + 1,
                                    testsep);
    assert_int_equal(ctx->one_two_three->size, 2);
    struct buffer *buf = buffer_list_peek(ctx->one_two_three);
    assert_buf_equals_str(buf, expected);
}

static void
test_buffer_list_aggregate_separator_all(void **state)
{
    struct test_buffer_list_aggregate_ctx *ctx = *state;

    /* Aggregate all */
    buffer_list_aggregate_separator(ctx->one_two_three, 1<<16, testsep);
    assert_int_equal(ctx->one_two_three->size, 1);
    struct buffer *buf = buffer_list_peek(ctx->one_two_three);
    assert_buf_equals_str(buf,
                          teststr1 testsep teststr2 testsep teststr3 testsep);
}

static void
test_buffer_list_aggregate_separator_nosep(void **state)
{
    struct test_buffer_list_aggregate_ctx *ctx = *state;

    /* Aggregate all */
    buffer_list_aggregate_separator(ctx->one_two_three, 1<<16, testnosep);
    assert_int_equal(ctx->one_two_three->size, 1);
    struct buffer *buf = buffer_list_peek(ctx->one_two_three);
    assert_buf_equals_str(buf, teststr1 teststr2 teststr3);
}

static void
test_buffer_list_aggregate_separator_zerolen(void **state)
{
    struct test_buffer_list_aggregate_ctx *ctx = *state;
    struct buffer_list *bl_zerolen = ctx->zero_length_strings;

    /* Aggregate all */
    buffer_list_aggregate_separator(bl_zerolen, 1<<16, testnosep);
    assert_int_equal(bl_zerolen->size, 1);
    struct buffer *buf = buffer_list_peek(bl_zerolen);
    assert_buf_equals_str(buf, "");
}

static void
test_buffer_list_aggregate_separator_emptybuffers(void **state)
{
    struct test_buffer_list_aggregate_ctx *ctx = *state;
    struct buffer_list *bl_emptybuffers = ctx->empty_buffers;

    /* Aggregate all */
    buffer_list_aggregate_separator(bl_emptybuffers, 1<<16, testnosep);
    assert_int_equal(bl_emptybuffers->size, 1);
    struct buffer *buf = buffer_list_peek(bl_emptybuffers);
    assert_int_equal(BLEN(buf), 0);
}
#endif

#if defined(IMPLEMENTATION_2_5)
static void
test_buffer_free_gc_one(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(1024, &gc);

    assert_ptr_equal(gc.list + 1, buf.data);
    free_buf_gc(&buf, &gc);
    assert_null(gc.list);

    gc_free(&gc);
}

static void
test_buffer_free_gc_two(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf1 = alloc_buf_gc(1024, &gc);
    struct buffer buf2 = alloc_buf_gc(1024, &gc);
    struct buffer buf3 = alloc_buf_gc(1024, &gc);

    struct gc_entry *e;

    e = gc.list;

    assert_ptr_equal(e + 1, buf3.data);
    assert_ptr_equal(e->next + 1, buf2.data);
    assert_ptr_equal(e->next->next + 1, buf1.data);

    free_buf_gc(&buf2, &gc);

    assert_non_null(gc.list);

    while (e)
    {
        assert_ptr_not_equal(e + 1, buf2.data);
        e = e->next;
    }

    gc_free(&gc);
}
#endif

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

int
main(int argc, char **argv)
{
    const struct CMUnitTest tests[] = {
#if defined(IMPLEMENTATION_2_4)
        cmocka_unit_test(test_buffer_strprefix),
#endif
#if defined(IMPLEMENTATION_2_2)
        cmocka_unit_test_setup_teardown(test_buffer_list_full,
                                        test_buffer_list_setup,
                                        test_buffer_list_teardown),
        cmocka_unit_test_setup_teardown(test_buffer_list_aggregate_separator_empty,
                                        test_buffer_list_setup,
                                        test_buffer_list_teardown),
        cmocka_unit_test_setup_teardown(test_buffer_list_aggregate_separator_noop,
                                        test_buffer_list_setup,
                                        test_buffer_list_teardown),
        cmocka_unit_test_setup_teardown(test_buffer_list_aggregate_separator_two,
                                        test_buffer_list_setup,
                                        test_buffer_list_teardown),
        cmocka_unit_test_setup_teardown(test_buffer_list_aggregate_separator_all,
                                        test_buffer_list_setup,
                                        test_buffer_list_teardown),
        cmocka_unit_test_setup_teardown(test_buffer_list_aggregate_separator_nosep,
                                        test_buffer_list_setup,
                                        test_buffer_list_teardown),
        cmocka_unit_test_setup_teardown(test_buffer_list_aggregate_separator_zerolen,
                                        test_buffer_list_setup,
                                        test_buffer_list_teardown),
        cmocka_unit_test_setup_teardown(test_buffer_list_aggregate_separator_emptybuffers,
                                        test_buffer_list_setup,
                                        test_buffer_list_teardown),
#endif
#if defined(IMPLEMENTATION_2_5)
        cmocka_unit_test(test_buffer_free_gc_one),
        cmocka_unit_test(test_buffer_free_gc_two),
#endif
    };

    do_getopt (argc, argv);

    int result = !!cmocka_run_group_tests_name("buffer", tests, NULL, NULL);
    if (!result && sizeof(tests) == 0)
        result = AUTOMAKE_TEST_SKIPPED;

    {
        /* If the test would otherwise pass, mark it as skipped
         * until a human validates that the #ifdefs around IMPLEMENTATION_x_x
         * are not wrong.
         *
         */
#if defined(IMPLEMENTATION_2_5)
        result = AUTOMAKE_TEST_HARD_ERROR;
        /* Force human to check that the test is checking all available features
         * in 2.5
         * If this is are reading this, and have checked that all features that
         * exist in 2.5 are enabled for testing, remove the result override in
         * this section.
         *
         * If the ifdefs have left a feature untested, add this condition to the
         * #if defined... for the wrongly skipped feature:
         * "|| defined(IMPLEMENTATION_2_5)"
         *
         * If after checking, the test does not cover any functions in this
         * branch, it's up to you to implement some tests.
         *
         * Then replace this comment with a note saying when 2.5 testing was
         * validated, and commit the change, and cherry-pick it to the tests
         * repo
         */
#elif defined(IMPLEMENTATION_2_4)
        /* 
         * I checked that no test features are accidentally disabled in the 2.3
         * branch. Ie, tests can can be performed in this branch, there are no
         * blindspots. However, feature coverage is pretty low, only aggregate
         * tests are done. More is needed.
         * Ie, a fail is deserved, and a pass is also deserved (but not earned)
         */
        /* Force human to check that the test is checking all available features
         * in 2.4
         * If this is are reading this, and have checked that all features that
         * exist in 2.4 are enabled for testing, remove the result override in
         * this section.
         *
         * If the ifdefs have left a feature untested, add this condition to the
         * #if defined... for the wrongly skipped feature:
         * "|| defined(IMPLEMENTATION_2_4)"
         *
         * If after checking, the test does not cover any functions in this
         * branch, it's up to you to implement some tests.
         *
         * Then replace this comment with a note saying when 2.4 testing was
         * validated, and commit the change, and cherry-pick it to the tests
         * repo
         */
#elif defined(IMPLEMENTATION_2_3)
        /* 
         * I checked that no test features are accidentally disabled in the 2.3
         * branch. Ie, tests can can be performed in this branch, there are no
         * blindspots. However, feature coverage is pretty low, only aggregate
         * tests are done. More is needed.
         * Ie, a fail is deserved, and a pass is also deserved (but not earned)
         */
#elif defined(IMPLEMENTATION_2_2)
        result = AUTOMAKE_TEST_HARD_ERROR;
        /* Force human to check that the test is checking all available features
         * in 2.2
         * If this is are reading this, and have checked that all features that
         * exist in 2.2 are enabled for testing, remove the result override in
         * this section.
         *
         * If the ifdefs have left a feature untested, add this condition to the
         * #if defined... for the wrongly skipped feature:
         * "|| defined(IMPLEMENTATION_2_2)"
         *
         * If after checking, the test does not cover any functions in this
         * branch, it's up to you to implement some tests.
         *
         * Then replace this comment with a note saying when 2.2 testing was
         * validated, and commit the change, and cherry-pick it to the tests
         * repo
         */
#elif defined(IMPLEMENTATION_2_0)
        result = AUTOMAKE_TEST_HARD_ERROR;
        /* Force human to check that the test is checking all available features
         * in 2.2
         * If this is are reading this, and have checked that all features that
         * exist in 2.2 are enabled for testing, remove the result override in
         * this section.
         *
         * If the ifdefs have left a feature untested, add this condition to the
         * #if defined... for the wrongly skipped feature:
         * "|| defined(IMPLEMENTATION_2_2)"
         *
         * If after checking, the test does not cover any functions in this
         * branch, it's up to you to implement some tests.
         *
         * Then replace this comment with a note saying when 2.2 testing was
         * validated, and commit the change, and cherry-pick it to the tests
         * repo
         */
#endif
    }

    return result;
}
