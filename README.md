# cti-pattern-matcher

*This is an [OASIS Open Repository](https://www.oasis-open.org/resources/open-repositories/). See the [Governance](#governance) section for more information.*

The pattern-matcher is a prototype software tool for matching STIX Observed Data content against patterns used in STIX Indicators. The matcher accepts a pattern and one or more timestamped observations, and determines whether the observations match the criteria specified by the pattern. The purpose of this tool is to evaluate examples and test cases which implement the patterning specification, as a form of executable documentation and to verify patterns express the desired criteria.

## Requirements

* Python 2.7.6+
* ANTLR Python Runtime (4.5.3+)
 * https://pypi.python.org/pypi/antlr4-python2-runtime (Python 2)
 * https://pypi.python.org/pypi/antlr4-python3-runtime (Python 3)
* python-dateutil (https://dateutil.readthedocs.io/en/stable/)
* six (https://six.readthedocs.io/)
* (For running tests) - pytest (http://pytest.org/latest/getting-started.html)

## Installation

To install pattern-matcher, first install all required dependencies, then run `python setup.py install` in the root of this repository. 

## Usage
Run the `pattern_matcher.py` script in this repository, and follow directions. For example:

```bash
$ python pattern_matcher.py

Enter a CybOX pattern:
file-object:hashes.sha-256 = 'aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f'

Enter the name of json file containing a CybOX object or container:
test\0pass.json

PASS: file-object:hashes.sha-256 = 'aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f'
```

## Testing

To run the automated tests, execute `py.test` from inside the `test` directory.

## Governance

This GitHub public repository ( **[https://github.com/oasis-open/cti-pattern-matcher](https://github.com/oasis-open/cti-pattern-matcher)** ) was [proposed](https://lists.oasis-open.org/archives/cti/201610/msg00106.html) and [approved](https://lists.oasis-open.org/archives/cti/201610/msg00126.html) [[bis](https://issues.oasis-open.org/browse/TCADMIN-2477)] by the [OASIS Cyber Threat Intelligence (CTI) TC](https://www.oasis-open.org/committees/cti/) as an [OASIS Open Repository](https://www.oasis-open.org/resources/open-repositories/) to support development of open source resources related to Technical Committee work.

While this Open Repository remains associated with the sponsor TC, its development priorities, leadership, intellectual property terms, participation rules, and other matters of governance are [separate and distinct](https://github.com/oasis-open/cti-pattern-matcher/blob/master/CONTRIBUTING.md#governance-distinct-from-oasis-tc-process) from the OASIS TC Process and related policies.

All contributions made to this Open Repository are subject to open source license terms expressed in the [BSD-3-Clause License](https://www.oasis-open.org/sites/www.oasis-open.org/files/BSD-3-Clause.txt). That license was selected as the declared ["Applicable License"](https://www.oasis-open.org/resources/open-repositories/licenses) when the Open Repository was created.

As documented in ["Public Participation Invited](https://github.com/oasis-open/cti-pattern-matcher/blob/master/CONTRIBUTING.md#public-participation-invited)", contributions to this OASIS Open Repository are invited from all parties, whether affiliated with OASIS or not. Participants must have a GitHub account, but no fees or OASIS membership obligations are required. Participation is expected to be consistent with the [OASIS Open Repository Guidelines and Procedures](https://www.oasis-open.org/policies-guidelines/open-repositories), the open source [LICENSE](https://github.com/oasis-open/cti-pattern-matcher/blob/master/LICENSE) designated for this particular repository, and the requirement for an [Individual Contributor License Agreement](https://www.oasis-open.org/resources/open-repositories/cla/individual-cla) that governs intellectual property.

### <a id="maintainers">Maintainers</a>

Open Repository [Maintainers](https://www.oasis-open.org/resources/open-repositories/maintainers-guide) are responsible for oversight of this project's community development activities, including evaluation of GitHub [pull requests](https://github.com/oasis-open/cti-pattern-matcher/blob/master/CONTRIBUTING.md#fork-and-pull-collaboration-model) and [preserving](https://www.oasis-open.org/policies-guidelines/open-repositories#repositoryManagement) open source principles of openness and fairness. Maintainers are recognized and trusted experts who serve to implement community goals and consensus design preferences.

Initially, the associated TC members have designated one or more persons to serve as Maintainer(s); subsequently, participating community members may select additional or substitute Maintainers, per [consensus agreements](https://www.oasis-open.org/resources/open-repositories/maintainers-guide#additionalMaintainers).

**<a id="currentMaintainers">Current Maintainers of this Open Repository</a>**

 * [Greg Back](mailto:gback@mitre.org); GitHub ID: [https://github.com/gtback/](https://github.com/gtback/); WWW: [MITRE](https://www.mitre.org/)
 * [Ivan Kirillov](mailto:ikirillov@mitre.org); GitHub ID: [https://github.com/ikiril01/](https://github.com/ikiril01/); WWW: [MITRE](https://www.mitre.org/)

## <a id="aboutOpenRepos">About OASIS Open Repositories</a>

 * [Open Repositories: Overview and Resources](https://www.oasis-open.org/resources/open-repositories/)
 * [Frequently Asked Questions](https://www.oasis-open.org/resources/open-repositories/faq)
 * [Open Source Licenses](https://www.oasis-open.org/resources/open-repositories/licenses)
 * [Contributor License Agreements (CLAs)](https://www.oasis-open.org/resources/open-repositories/cla)
 * [Maintainers' Guidelines and Agreement](https://www.oasis-open.org/resources/open-repositories/maintainers-guide)

## <a id="feedback">Feedback</a>

Questions or comments about this Open Repository's activities should be composed as GitHub issues or comments. If use of an issue/comment is not possible or appropriate, questions may be directed by email to the Maintainer(s) [listed above](#currentMaintainers). Please send general questions about Open Repository participation to OASIS Staff at [repository-admin@oasis-open.org](mailto:repository-admin@oasis-open.org) and any specific CLA-related questions to [repository-cla@oasis-open.org](mailto:repository-cla@oasis-open.org).
