# Unit Test Framework

Contents


## Introduction

This directory contains unit tests for various feature used in OpenVPN.

Each subdirectory holds tests against one specific feature.

## Adding New Tests for new features

Tests for new features can use the tests in "base64" as a template.

Integrating the new test into the test suite requires the following steps (
assume the feature name is 'letmein'):

1. Check out the tests repo.

1. Declare the implementation in [configure.ac](../../configure.ac), "above End Feature Implementations"

   1. If the feature is to be newly implemented:
   Example:

   ```AM_CONDITIONAL([IMPLEMENTED_letmein], [false])```

   2. If the feature already exists, its presence must be detected:
   Example:
   ```AM_CONDITIONAL([IMPLEMENTED_base64], [test -f $(dirname "$srcdir/$ac_unique_file")/base64.c])```

    This ensures that the test suite will be correctly disabled when it is merged into a source tree pre-dating the feature's introduction.

2. Declare the unit test in [configure.ac](../../configure.ac), above "End Feature Unit Tests"
   Example:
```
AM_COND_IF([IMPLEMENTED_letmein],
    [AC_CONFIG_FILES(tests/unit/letmein/Makefile) implemented=yes])
AM_CONDITIONAL([UNIT_TESTED_letmein], [test "$implemented" = "yes" ])
```

3. Copy an existing test subdirectory as a starting point (eg, base64 or others)

4. Name the new tests appropriately (see [Naming](#Naming-Tests) section below)

5. Add the unit-test SUBDIR to tests/unit/Makefile.am, below `if ENABLE_UNITTESTS`
   Example:

```
if IMPLEMENTED_letmein
SUBDIRS += unit/letmein
endif
```

6. Commit to the **tests** repo

7. Check out the source repo and merge the tests repo into the source tree.

8. Change IMPLEMENTED_letmein conditional to "true", and implement the feature.

9. When committing, commit the IMPLEMENT_letmein conditional set to true in the same
   commit as the source code, but nothing from the tests/ directory.

10. Commit changes to tests/ as a separate commit from any source tree changes,
    including documentation, makefiles, changes. The commit has to be cherry-picked
    into the tests repo. Note, in the tests repo, all IMPLEMENTED_ conditionals
    will be either [false] or [test -f ...] (detection), but never [true]



## Naming Tests

The test extension is used to distinguish what testdriver program will be used to run the test. New extensions may be added in the future. The authoritative list is in [srcpaths.inc](srcpaths.inc). Here is a (possibly outdated) list

Extension | Use Scenario
----------|-------------
.test     | Functionality/behaviour tests. Typically use the cmocka library for assertion checking.
.memcheck | Build will be run with [valgrind --tool=memcheck](https://valgrind.org/docs/manual/mc-manual.html)
.conf     | This is a configuration file. It will be run through a configuration checker (TODO: implement this testdriver)
.perf     | Performance test. Check that the time complexity (O(n)) is acceptable. (TODO: implement this testdriver)

The basename of a test is used to distinguish what general functional area the test covers. Using one of these names makes it
easy for developers to run a subset of the test suite. This will be increasingly important to save time as the test-suite
grows, and its runtime becomes significant. For instance, to all algorithm tests, you could run `make check TESTS=algo`

Basename | Use Scenario
---------|-------------
base     | Behaviour test that don't fit on one of the descriptions below.
sanity   | Tests that prove the active configuration is sane. These are run by package maintainers, and may include any tests that could be described with more specificity.
algo     | Algorithm tests, eg, hashes, encryption, base64, RTT calculations
protocol | Communication tests, emphasising interface protocols (eg, management interface, client-server communications, program-OS interactions like `ifconfig` syntax, netlink message interpretation, error queue interpretations)
auth     | Authentication tests like cert verification, user/password stuff, challenge/response
time     | Timekeeping tests, checking for race conditions, timeout scheduling
net      | Network tests, involving socket operations.
memleaks | Test instrumented specifically for detecting memory leaks, buffer over/under flow, uninitialized variables. Typically "memleaks.{somename}.memcheck", so it is run under valgrind.

### Naming example

Suppose a feature implements authentication, named "letmein". It allocates memory, so there is a potential for leaks, and has some configuration requirements (conflicts with some other config options). It is implemented in the file `letmein.c` in the source tree. How to set it up:

* Unit test directory name = `letmein`
* Behaviour tests = `letmein/test.c`
* Basename for the test = `auth`
* Extension(s) = `.test`, `.memcheck`, `.conf`
* The prog_SOURCE lists for the `test` and `memcheck` targets should be `test.c $(openvpn_srcdir)/letmein.c`
* Several configurations may be useful to test. Add them to the `TESTS` variable in Makefile.am (no SOURCE needed, and do not require building)
  * `auth.basic.conf`
  * `auth.challenge-response.conf`
  * `auth.challenge-or-password.conf`
  * `auth.conflict-with-otherauth.conf` (also add to `XFAIL_TESTS = auth.conflict-with-otherauth.conf` if this should be detected as an invalid configuration, ie "eXpected to FAIL")
* The following targets should be built, all using the same SOURCES, LIBRARIES and possibly FLAGS: 
  * `auth.test`
  * `auth.memcheck`

What this enables:
* To test all authentication implementations: `make check TESTS=auth`
* To test only this example implementation: `make -C tests/letmein`
* When the test runs, there will be separate pass/fail reports for:
  * behaviour of the test (return value of `auth.test`)
  * memory leaks, using unitinialized memory (return value of [valgrind --tool=memcheck](https://valgrind.org/docs/manual/mc-manual.html))
  * good configuration is accepted
  * invalid configuration is detected

## Maintenance

The unit tests will normally be developed in the source repo, but once they are complete, they should be cherry-picked into the tests repo, to make them available to run on both older versions of the project, and newer.

When the tests are updated in the future, eg to add regression testing for bugs found later, the updates should also be cherry-picked into the tests repo. This will allow the tests repo to be merged into older project branches to test older implementations against the newly found bug. If the bug was recently introduced, older versions may pass, but if they don't, having an up-to-date test will enable bugfixes against old versions to be done with confidence.
