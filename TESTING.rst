..
      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.


      Convention for heading levels in GBP devref:
      =======  Heading 0 (reserved for the title in a document)
      -------  Heading 1
      ~~~~~~~  Heading 2
      +++++++  Heading 3
      '''''''  Heading 4
      (Avoid deeper levels because they do not render well.)


Testing GBP
===============


Running Tests
-------------

There are two mechanisms for running tests: run_tests.sh, and tox.
Before submitting a patch for review you should always
ensure all test pass; a tox run is triggered by the jenkins gate
executed on gerrit for each patch pushed for review.

With these mechanisms you can either run the tests in the standard
environment or create a virtual environment to run them in.

By default after running all of the tests, any pep8 errors
found in the tree will be reported.


With `run_tests.sh`
~~~~~~~~~~~~~~~~~~~

You can use the `run_tests.sh` script in the root source directory to execute
tests in a virtualenv::

    ./run_tests -V


With `tox`
~~~~~~~~~~

GBP, like other OpenStack projects, uses `tox`_ for managing the virtual
environments for running test cases. It uses `Testr`_ for managing the running
of the test cases.

Tox handles the creation of a series of `virtualenvs`_ that target specific
versions of Python.

Testr handles the parallel execution of series of test cases as well as
the tracking of long-running tests and other things.

For more information on the standard Tox-based test infrastructure used by
OpenStack and how to do some common test/debugging procedures with Testr,
see this wiki page:

  https://wiki.openstack.org/wiki/Testr

.. _Testr: https://wiki.openstack.org/wiki/Testr
.. _tox: http://tox.readthedocs.org/en/latest/
.. _virtualenvs: https://pypi.python.org/pypi/virtualenv

PEP8 and Unit Tests
+++++++++++++++++++

Running pep8 and unit tests is as easy as executing this in the root
directory of the GBP source code::

    tox

To run only pep8::

    tox -e pep8

To restrict pep8 check to only the files altered by the latest patch changes::

    tox -e pep8 HEAD~1

To run only the unit tests::

    tox -e py27


Running Individual Tests
~~~~~~~~~~~~~~~~~~~~~~~~

For running individual test modules, cases or tests, you just need to pass
the dot-separated path you want as an argument to it.

For example, the following would run only a single test or test case::

      $ ./run_tests.sh gbpservice.neutron.tests.unit.test_extension_group_policy
      $ ./run_tests.sh gbpservice.neutron.tests.unit.test_extension_group_policy.GroupPolicyExtensionTestCase
      $ ./run_tests.sh gbpservice.neutron.tests.unit.test_extension_group_policy.GroupPolicyExtensionTestCase.test_create_policy_target

or::

      $ tox -e py27 gbpservice.neutron.tests.unit.test_extension_group_policy
      $ tox -e py27 gbpservice.neutron.tests.unit.test_extension_group_policy.GroupPolicyExtensionTestCase
      $ tox -e py27 gbpservice.neutron.tests.unit.test_extension_group_policy.GroupPolicyExtensionTestCase.test_create_policy_target

If you want to pass other arguments to ostestr, you can do the following::
      $ tox -e -epy27 -- --regex gbpservice.neutron.tests.unit.test_extension_group_policy --serial


Coverage
--------

To get a grasp of the areas where tests are needed, you can check
current unit tests coverage by running::

    $ ./run_tests.sh -c

or by running::

    $ tox -ecover

Note that this is also useful to run before submitting a new patchset
to ensure that the new code you are introducing has adequate unit test
coverage.


Debugging
---------

By default, calls to pdb.set_trace() will be ignored when tests
are run. For pdb statements to work, invoke run_tests as follows::

    $ ./run_tests.sh -d [test module path]

It's possible to debug tests in a tox environment::

    $ tox -e venv -- python -m testtools.run [test module path]

Tox-created virtual environments (venv's) can also be activated
after a tox run and reused for debugging::

    $ tox -e venv
    $ . .tox/venv/bin/activate
    $ python -m testtools.run [test module path]

Tox packages and installs the GBP source tree in a given venv
on every invocation, but if modifications need to be made between
invocation (e.g. adding more pdb statements), it is recommended
that the source tree be installed in the venv in editable mode::

    # run this only after activating the venv
    $ pip install --editable .

Editable mode ensures that changes made to the source tree are
automatically reflected in the venv, and that such changes are not
overwritten during the next tox run.

Post-mortem Debugging
~~~~~~~~~~~~~~~~~~~~~

Setting OS_POST_MORTEM_DEBUGGER in the shell environment will ensure
that the debugger .post_mortem() method will be invoked on test failure::

    $ OS_POST_MORTEM_DEBUGGER=pdb ./run_tests.sh -d [test module path]

Supported debuggers are pdb, and pudb. Pudb is full-screen, console-based
visual debugger for Python which let you inspect variables, the stack,
and breakpoints in a very visual way, keeping a high degree of compatibility
with pdb::

    $ ./.venv/bin/pip install pudb

    $ OS_POST_MORTEM_DEBUGGER=pudb ./run_tests.sh -d [test module path]

References
~~~~~~~~~~

.. [#pudb] PUDB debugger:
   https://pypi.python.org/pypi/pudb
