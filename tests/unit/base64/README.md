This directory contains unit tests for a "base64" feature used in OpenVPN.

The tests were added long after the feature was implemented and proven in
operation, so nothing meaningful is actually tested.

However, the testsuite was added recently, and these tests are an example of how
to add and maintain unit tests.

Tests like this one should be committed (eg, cherry-picked) into the tests repo
and will be able to run on any version of the OpenVPN project, not only versions
newer than the test. The point of the tests repo is to be merged into any
OpenVPN source repo, new or ancient, and to provide the tip-of-the branch
quality tests to any old snapshot, thus enabling backtesting, and bug-fixing
in older versions of the project.

These tests can be used as template for 'real' tests, whether against existing/
legacy features or new features.
