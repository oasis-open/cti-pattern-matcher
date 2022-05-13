import pytest

from stix2matcher.matcher import match

_stix_version = '2.1'
_observations = [
    {
        "type": "bundle",
        "id": "bundle--d33ba274-6623-4ff9-af64-0e2d17de9bbe",
        "objects": [
            {
                "id": "observed-data--0eae5c46-70ee-4bee-8d3d-48aa8cb610a4",
                "type": "observed-data",
                "number_observed": 1,
                "first_observed": "2011-12-03T21:34:41Z",
                "last_observed": "2011-12-03T21:34:41Z",
                "objects": {},
                "object_refs": [
                    "binary_test--d4a7a685-e929-4eec-a746-4196e447d33d"
                ],
                "spec_version": "2.1"
            },
            {
                "type": "binary_test",
                "name": "alice",
                "name_u": "\u0103lice",
                "name_hex": "616c696365",
                "name_bin": "YWxpY2U=",
                "bin_hex": "01020304",
                "id": "binary_test--d4a7a685-e929-4eec-a746-4196e447d33d"
            }
        ]
    }
]


@pytest.mark.parametrize("pattern", [
    "[binary_test:name = h'616c696365']",
    "[binary_test:name = b'YWxpY2U=']",
    "[binary_test:name_bin = h'616c696365']",
    "[binary_test:name_bin = b'YWxpY2U=']",
    "[binary_test:name_bin = 'alice']",
    "[binary_test:name_hex = h'616c696365']",
    "[binary_test:name_hex = b'YWxpY2U=']",
    "[binary_test:name_hex = 'alice']",

    "[binary_test:name > h'616172647661726b']",
    "[binary_test:name > b'YWFyZHZhcms=']",
    "[binary_test:name_bin > h'616172647661726b']",
    "[binary_test:name_bin > b'YWFyZHZhcms=']",
    "[binary_test:name_bin > 'aardvark']",
    "[binary_test:name_hex > h'616172647661726b']",
    "[binary_test:name_hex > b'YWFyZHZhcms=']",
    "[binary_test:name_hex > 'aardvark']",

    "[binary_test:name_hex MATCHES '\\\\x61li[c\\\\x01]e']",
    "[binary_test:name_bin MATCHES '\\\\x61li[c\\\\x01]e']",
    "[binary_test:name_bin NOT MATCHES '\\\\x62o[b\\\\x01]']",
    u"[binary_test:name_bin NOT MATCHES '\u0103lice']",

    "[binary_test:name_bin LIKE '%alice%']",
    "[binary_test:name_bin LIKE 'alice']",
    "[binary_test:name_bin NOT LIKE '%\u0103lice%']",
    "[binary_test:name_bin NOT LIKE '%aardvark%']",

    # some nonprintable binary data tests too.
    "[binary_test:bin_hex = h'01020304']",
    "[binary_test:bin_hex = b'AQIDBA==']",
    "[binary_test:bin_hex = '\x01\x02\x03\x04']",
    "[binary_test:bin_hex MATCHES '.*\\\\x03']",
])
def test_binary_match(pattern):
    assert match(pattern, _observations, stix_version=_stix_version)


@pytest.mark.parametrize("pattern", [
    "[binary_test:name_bin MATCHES '\\\\x62o[b\\\\x01]']",
    "[binary_test:name_hex NOT MATCHES '\\\\x61li[c\\\\x01]e']",

    # test codepoint >= 256, in both pattern and json
    u"[binary_test:name_bin = '\u0103lice']",
    u"[binary_test:name_bin > '\u0103lice']",
    u"[binary_test:name_bin < '\u0103lice']",
    u"[binary_test:name_bin LIKE '\u0103lice']",
    u"[binary_test:name_bin MATCHES '\u0103lice']",
    u"[binary_test:name_hex = '\u0103lice']",
    u"[binary_test:name_hex > '\u0103lice']",
    u"[binary_test:name_hex < '\u0103lice']",
    u"[binary_test:name_hex MATCHES '\u0103lice']",
    u"[binary_test:name_u = h'616c696365']",
    u"[binary_test:name_u > h'616c696365']",
    u"[binary_test:name_u < h'616c696365']",
    u"[binary_test:name_u = b'YWxpY2U=']",
    u"[binary_test:name_u > b'YWxpY2U=']",
    u"[binary_test:name_u < b'YWxpY2U=']",
])
def test_binary_nomatch(pattern):
    assert not match(pattern, _observations, stix_version=_stix_version)
