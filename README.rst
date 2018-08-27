|Build_Status| |Coverage|

cti-pattern-matcher
===================

This is an `OASIS TC Open
Repository <https://www.oasis-open.org/resources/open-
repositories/>`__.
See the `Governance <#governance>`__ section for more information.

The pattern-matcher is a prototype software tool for matching STIX
Observed Data content against patterns used in STIX Indicators. The
matcher accepts a pattern and one or more timestamped observations,
and
determines whether the observations match the criteria specified by
the
pattern. The purpose of this tool is to evaluate examples and test
cases
which implement the patterning specification, as a form of executable
documentation and to verify patterns express the desired criteria.

Requirements
------------

-  Python 2.7 or 3.4+
-  ANTLR Python Runtime (4.7+)

   -  https://pypi.python.org/pypi/antlr4-python2-runtime (Python 2)
   -  https://pypi.python.org/pypi/antlr4-python3-runtime (Python 3)

-  typing

   -  https://pypi.python.org/pypi/typing (Python 3.4)

-  python-dateutil (https://dateutil.readthedocs.io/en/stable/)
-  six (https://six.readthedocs.io/)
-  (For running tests) - pytest (http://pytest.org/latest/getting-started.html)

Installation
------------

To install pattern-matcher, first install all required dependencies,
then run ``python setup.py install`` in the root of this repository.

Usage
-----

Installing the package creates a ``stix2-matcher`` script:

::

    $ stix2-matcher -h
    usage: stix2-matcher [-h] -p PATTERNS -f FILE [-e ENCODING] [-v]

    Match STIX Patterns to STIX Observed Data

    optional arguments:
      -h, --help            show this help message and exit
      -p PATTERNS, --patterns PATTERNS
                            Specify a file containing STIX Patterns,
                            one per line.
      -f FILE, --file FILE  A file containing JSON list of STIX
      observed-data SDOs
                            to match against.
      -e ENCODING, --encoding ENCODING
                            Set encoding used for reading observation
                            and pattern
                            files. Must be an encoding name Python
                            understands.
                            Default is utf8.
      -v, --verbose         Be verbose

Testing
-------

The STIX Pattern Matcher’s test suite can be run with `pytest`_.

Updating the Grammar
--------------------

The ANTLR pattern grammar is maintained in the `stix2-json-schemas`_
repository. If the grammar changes, the code in this repository should
be updated to match. To do so, use the Java ANTLR package to generate
new Python source files. (The .jar file is not needed for normal use
of
the validator).

1. Download antlr-4.7-complete.jar from http://www.antlr.org/download/
2. Clone the stix2-json-schemas repository or download the
   STIXPattern.g4 file.
3. Change to the directory containing the STIXPattern.g4 file.
4. Run the following command

   .. code:: bash

       $ java -jar "/path/to/antlr-4.7-complete.jar" -Dlanguage=Python2 STIXPattern.g4 -o /path/to/cti-pattern-matcher/stix2matcher/grammars

5. Commit the resulting files to git.

Governance
----------

This GitHub public repository (
**https://github.com/oasis-open/cti-pattern-matcher** ) was
`proposed`_
and `approved`_ [`bis`_] by the `OASIS Cyber Threat Intelligence (CTI)
TC`_ as an `OASIS TC Open Repository`_ to support development of open
source resources related to Technical Committee work.

While this TC Open Repository remains associated with the sponsor TC,
its
development priorities, leadership, intellectual property terms,
participation rules, and other matters of governance are `separate and
distinct`_ from the OASIS TC Process and related policies.

All contributions made to this TC Open Repository are subject to open
source license terms expressed in the `BSD-3-Clause License`_. That
license was selected as the declared `“Applicable License”`_ when the
TC Open Repository was created.

As documented in `“Public Participation Invited`_\ “, contributions to
this OASIS TC Open Repository are invited from all parties, whether
affiliated with OASIS or not. Participants must have a GitHub account,
but no fees or OASIS membership obligations are required.
Participation
is expected to be consistent with the `OASIS TC Open Repository
Guidelines
and Procedures`_, the open source `LICENSE`_ designated for this
particular repository, and the requirement for an `Individual
Contributor License Agreement`_ that governs intellectual property.

Maintainers
-----------

TC Open Repository `Maintainers`_ are responsible for oversight of
this
project’s community development activities, including evaluation of
GitHub `pull requests`_ and `preserving`_ open source principles of
openness and fairness. Maintainers are recognized and trusted experts
who serve to implement community goals and consensus design
preferences.

Initially, the associated TC members have designated one or more
persons
to serve as Maintainer(s); subsequently, participating community
members
may select additional or substitute Maintainers, per `consensus
agreements`_.

**Current Maintainers of this TC Open Repository**

-  `Chris Lenk`_; GitHub ID: https://github.com/clenk/; WWW: `MITRE`_
-  `Ivan Kirillov`_; GitHub ID: https://github.com/ikiril01/; WWW:
   `MITRE`_

About OASIS TC Open Repositories
-----------------------------

-  `TC Open Repositories - Overview and Resources`_
-  `Frequently Asked Questions`_
-  `Open Source Licenses`_
-  `Contributor License Agreements (CLAs)`_
-  `Maintainers’ Guidelines and Agreement`_

Feedback
--------

Questions or comments about this TC Open Repository’s activities
should be
composed as GitHub issues or comments. If use of an issue/comment is
not
possible or appropriate, questions may be directed by email to the
Maintainer(s) `listed above <#currentmaintainers>`__. Please send
general questions about Open
Repository participation to OASIS Staff at
repository-admin@oasis-open.org and any specific CLA-related questions
to repository-cla@oasis-open.org.

.. _`TC Open Repositories - Overview and Resources`: https://www.oasis-open.org/resources/open-repositories/
.. _Frequently Asked Questions: https://www.oasis-open.org/resources/open-repositories/faq
.. _Open Source Licenses: https://www.oasis-open.org/resources/open-repositories/licenses
.. _Contributor License Agreements (CLAs): https://www.oasis-open.org/resources/open-repositories/cla
.. _Maintainers’ Guidelines and Agreement: https://www.oasis-open.org/resources/open-repositories/maintainers-guide
.. _Maintainers: https://www.oasis-open.org/resources/open-repositories/maintainers-guide
.. _pull requests: https://github.com/oasis-open/cti-pattern-matcher/blob/master/CONTRIBUTING.md#fork-and-pull-collaboration-model
.. _preserving: https://www.oasis-open.org/policies-guidelines/open-repositories#repositoryManagement
.. _consensus agreements: https://www.oasis-open.org/resources/open-repositories/maintainers-guide#additionalMaintainers
.. _Chris Lenk: mailto:clenk@mitre.org
.. _MITRE: https://www.mitre.org/
.. _Ivan Kirillov: mailto:ikirillov@mitre.org
.. _proposed: https://lists.oasis-open.org/archives/cti/201610/msg00106.html
.. _approved: https://lists.oasis-open.org/archives/cti/201610/msg00126.html
.. _bis: https://issues.oasis-open.org/browse/TCADMIN-2477
.. _OASIS Cyber Threat Intelligence (CTI) TC: https://www.oasis-open.org/committees/cti/
.. _separate and distinct: https://github.com/oasis-open/cti-pattern-matcher/blob/master/CONTRIBUTING.md#governance-distinct-from-oasis-tc-process
.. _BSD-3-Clause License: https://www.oasis-open.org/sites/www.oasis-open.org/files/BSD-3-Clause.txt
.. _“Applicable License”: https://www.oasis-open.org/resources/open-repositories/licenses
.. _“Public Participation Invited: https://github.com/oasis-open/cti-pattern-matcher/blob/master/CONTRIBUTING.md#public-participation-invited
.. _OASIS TC Open Repository Guidelines and Procedures: https://www.oasis-open.org/policies-guidelines/open-repositories
.. _LICENSE: https://github.com/oasis-open/cti-pattern-matcher/blob/master/LICENSE
.. _Individual Contributor License Agreement: https://www.oasis-open.org/resources/open-repositories/cla/individual-cla
.. _pytest: http://pytest.org
.. _stix2-json-schemas: https://github.com/oasis-open/cti-stix2-json-schemas/blob/master/pattern_grammar/STIXPattern.g4

.. |Build_Status| image:: https://travis-ci.org/oasis-open/cti-pattern-matcher.svg?branch=master
   :target: https://travis-ci.org/oasis-open/cti-pattern-matcher
.. |Coverage| image:: https://codecov.io/gh/oasis-open/cti-pattern-matcher/branch/master/graph/badge.svg
   :target: https://codecov.io/gh/oasis-open/cti-pattern-matcher
