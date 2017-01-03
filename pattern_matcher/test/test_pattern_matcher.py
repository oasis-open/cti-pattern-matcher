'''
Test cases for pattern_matcher.py.
'''
import datetime
import dateutil.tz
import json
import os
import pytest

from pattern_matcher.matcher import match


THIS_DIR = os.path.dirname(__file__)


def get_object_from_file(filename):
    path = os.path.abspath(os.path.join(THIS_DIR, filename))
    with open(path, "r") as f:
        return json.load(f)


TEST = 'testcases/'

###############################################################################
# TEST CASES FROM CYBOX 3.0 SPEC
###############################################################################

TEST_CASES = [
    "[file-object:hashes.sha-256 = 'aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f']",
    "[ipv4addr-object:value ISSUBSET '192.168.0.1/24']",
    "[emailaddr-object:value MATCHES /.+\\@ibm\\.com$/ AND file-object:name MATCHES /^Final Report.+\\.exe$/]",
    "[file-object:hashes.sha-256 = 'aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f' AND file-object:mime-type = 'application/x-pdf']",
    """
    [file-object:hashes.sha-256 = 'bf07a7fbb825fc0aae7bf4a1177b2b31fcf8a3feeaf7092761e18c859ee52a9c']
    ALONGWITH
    [file-object:hashes.sha-256 = 'aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f']""",
    """
    [file-object:hashes.md5 = '79054025255fb1a26e4bc422aef54eb4']
    FOLLOWEDBY
    [win-registry-key-object:key = 'hkey_local_machine\\foo\\bar'] WITHIN 5 MINUTES""",
    """
    ([user-account-object:value = 'Peter']
    ALONGWITH
    [user-account-object:value = 'Paul']
    ALONGWITH
    [user-account-object:value = 'Mary']) WITHIN 5 MINUTES""",
    "[artifact-object:mime-type = 'application/vnd.tcpdump.pcap' AND artifact-object:payload MATCHES /Zm9vYmFy/]",
    "[network-connection-object:extended_properties[0].source_payload MATCHES /dGVzdHRlc3R0ZXN0/]",
    "[file-object:size IN (32, 64, 641028)]",
    "[network-connection-object:extended_properties[*].source_payload MATCHES /dGVzdHRlc3R0ZXN0/]",
    """[file-object:file_system_properties.file_path.delimiter = '\\'
    AND file-object:file_system_properties.file_path.components[0] = 'C:'
    AND file-object:file_system_properties.file_path.components[1] = 'Windows'
    AND file-object:file_system_properties.file_path.components[2] = 'System32'
    AND file-object:file_system_properties.file_name = 'foo.dll']""",
    "[file-object:extended_properties.windows_pebinary.sections[*].entropy > 7.0]",
    "[Artifact:log = 'Login failed.'] REPEATS 5 TIMES",
    "[file-object:size > 30 or file-object:size > 9999999 and file-object:size < 0]",  # verify operator precedence
]

PASS_CASES = [(TEST_CASES[0], TEST + '0pass.json'),
              (TEST_CASES[1], TEST + '1pass.json'),
              (TEST_CASES[3], TEST + '3pass.json'),
              (TEST_CASES[4], TEST + '4pass.json'),
              (TEST_CASES[7], TEST + '8pass.json'),
              (TEST_CASES[8], TEST + '9pass.json'),
              (TEST_CASES[9], TEST + '10pass.json'),
              (TEST_CASES[10], TEST + '11pass.json'),
              (TEST_CASES[10], TEST + '11pass1.json'),
              (TEST_CASES[11], TEST + '12pass.json'),
              (TEST_CASES[12], TEST + '13pass.json'),
              (TEST_CASES[13], TEST + '14pass.json'),
              (TEST_CASES[14], TEST + '10pass.json'),
              ]


@pytest.mark.parametrize("pattern, filename", PASS_CASES)
def test_pass_patterns(pattern, filename):
    '''
    Match patterns against files containing valid CybOX objects which
    should pass.
    '''
    pass_test = False
    # dummy timestamp for now
    now = datetime.datetime.now(dateutil.tz.tzutc())

    cybox_containers = get_object_from_file(filename)
    if cybox_containers is not None:
        pass_test = match(pattern, cybox_containers,
                          [now] * len(cybox_containers))
    assert pass_test


FAIL_CASES = [(TEST_CASES[0], TEST + '0fail1.json'),
              (TEST_CASES[0], TEST + '0fail2.json'),
              (TEST_CASES[1], TEST + '1fail1.json'),
              (TEST_CASES[1], TEST + '1fail2.json'),
              (TEST_CASES[3], TEST + '3fail1.json'),
              (TEST_CASES[3], TEST + '3fail2.json'),
              (TEST_CASES[4], TEST + '4fail1.json'),
              (TEST_CASES[4], TEST + '4fail2.json'),
              (TEST_CASES[8], TEST + '8fail1.json'),
              (TEST_CASES[8], TEST + '8fail2.json'),
              (TEST_CASES[9], TEST + '9fail1.json'),
              (TEST_CASES[9], TEST + '9fail2.json'),
              (TEST_CASES[10], TEST + '10fail1.json'),
              (TEST_CASES[10], TEST + '10fail2.json'),
              (TEST_CASES[11], TEST + '11fail1.json'),
              (TEST_CASES[11], TEST + '11fail2.json'),
              (TEST_CASES[12], TEST + '12fail1.json'),
              (TEST_CASES[12], TEST + '12fail2.json'),
              (TEST_CASES[13], TEST + '14fail1.json'),
              (TEST_CASES[13], TEST + '13fail2.json'),
              ]


@pytest.mark.parametrize("pattern, filename", FAIL_CASES)
def test_fail_patterns(pattern, filename):
    '''
    Match patterns against files containing valid CybOX objects which
    should fail.
    '''
    pass_test = False
    # dummy timestamp for now
    now = datetime.datetime.now(dateutil.tz.tzutc())

    cybox_containers = get_object_from_file(filename)
    if cybox_containers is not None:
        pass_test = match(pattern, cybox_containers,
                          [now] * len(cybox_containers))
    assert not pass_test
