import pytest

from stix2matcher.matcher import match, MatcherException

_observations = [
    {
        "type": "observed-data",
        "first_observed": "1994-11-29T13:37:52Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": u"person",
                "name": u"alice"
            }
        }
    },
    {
        "type": "observed-data",
        "first_observed": "1994-11-29T13:37:57Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": u"person",
                "name": u"bob"
            }
        }
    },
    {
        "type": "observed-data",
        "first_observed": "1994-11-29T13:38:02Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": u"person",
                "name": u"carol"
            }
        }
    }
]


@pytest.mark.parametrize("pattern", [
    # WITHIN tests
    "[person:name = 'bob'] within 1 seconds",
    "[person:name = 'bob'] within .0001 seconds",
    "[person:name = 'alice'] and [person:name < 'carol'] within 1 seconds",
    "([person:name = 'alice'] and [person:name < 'carol']) within 5 seconds",
    "([person:name = 'alice'] and [person:name < 'carol']) within 6 seconds",
    "([person:name = 'alice'] or [person:name = 'darlene']) within 1 seconds",

    # START/STOP tests
    "[person:name = 'bob'] start '1994-11-29T13:37:57Z' stop '1994-11-29T13:37:58Z'",
    "[person:name like 'a%'] and [person:name = 'bob'] start '1994-11-29T13:37:57Z' stop '1994-11-29T13:37:58Z'",
    "([person:name like 'a%'] and [person:name = 'bob']) start '1994-11-29T13:37:50Z' stop '1994-11-29T13:37:58Z'",
    "[person:name = 'alice'] or [person:name = 'darlene'] start '1994-11-29T13:37:57Z' stop '1994-11-29T13:37:58Z'",
    "([person:name = 'alice'] or [person:name = 'darlene']) start '1994-11-29T13:37:52Z' stop '1994-11-29T13:37:58Z'",
    "[person:name matches ''] repeats 2 times start '1994-11-29T13:37:50Z' stop '1994-11-29T13:37:58Z'",
])
def test_temp_qual_match(pattern):
    assert match(pattern, _observations)


@pytest.mark.parametrize("pattern", [
    # WITHIN tests
    "([person:name = 'alice'] and [person:name < 'carol']) within 4 seconds",
    "([person:name = 'alice'] and [person:name < 'carol']) within 4.9999 seconds",
    "[person:name = 'elizabeth'] within 10 seconds",
    "([person:name < 'alice'] or [person:name = 'darlene']) within 10 seconds",

    # START/STOP tests
    "[person:name = 'bob'] start '1994-11-29T13:37:58Z' stop '1994-11-29T13:37:58Z'",
    "[person:name = 'bob'] start '1994-11-29T13:37:59Z' stop '1994-11-29T13:37:58Z'",
    "[person:name = 'bob'] start '1994-11-29T13:37:58Z' stop '1994-11-29T13:37:59Z'",
    "([person:name like 'a%'] and [person:name = 'bob']) start '1994-11-29T13:37:50Z' stop '1994-11-29T13:37:57Z'",
    "([person:name like 'z%'] or [person:name = 'darlene']) start '1994-11-29T13:37:50Z' stop '1994-11-29T13:37:57Z'",
    "[person:name matches ''] repeats 3 times start '1994-11-29T13:37:50Z' stop '1994-11-29T13:37:58Z'",
    "[person:name not like 'foo'] start '1994-11-29T13:37:50Z' stop '1994-11-29T13:37:57Z' repeats 3 times",
])
def test_temp_qual_nomatch(pattern):
    assert not match(pattern, _observations)


@pytest.mark.parametrize("pattern", [
    # WITHIN tests
    "[person:name = 'alice'] within 0 seconds",
    "[person:name = 'alice'] within 1 second",
    "[person:name = 'alice'] within -123.367 seconds",

    # START/STOP tests
    "[person:name = 'hannah'] start '1994-11-29t13:37:58Z' stop '1994-11-29T13:37:58Z'",
    "[person:name = 'hannah'] start '1994-11-29T13:37:58Z' stop '1994-11-29T13:37:58z'",
    "[person:name = 'hannah'] start '1994-11-29t13:37:58Z' stop '1994-11-29T13:37:58'",
    "[person:name = 'hannah'] start '1994-11-29T13:37Z' stop '1994-11-29T13:37:58Z'",
    "[person:name = 'hannah'] start '1994-11-29T13:37:58Z'",
])
def test_temp_qual_error(pattern):
    with pytest.raises(MatcherException):
        match(pattern, _observations)
