import pytest

from stix2matcher.matcher import match

_observations = [
    {
        "type": "observed-data",
        "first_observed": "2004-10-11T21:44:58Z",
        "last_observed": "2004-10-11T21:44:58Z",
        "number_observed": 2,
        "objects": {
            "a0": {
                "type": u"person",
                "name": u"alice",
                "age": 10
            }
        }
    },
    {
        "type": "observed-data",
        "first_observed": "2004-10-11T21:45:01Z",
        "last_observed": "2004-10-11T21:45:01Z",
        "number_observed": 3,
        "objects": {
            "b0": {
                "type": u"person",
                "name": u"bob",
                "age": 17
            }
        }
    },
    {
        "type": "observed-data",
        "first_observed": "2004-10-11T21:45:02Z",
        "last_observed": "2004-10-11T21:45:02Z",
        "number_observed": 2,
        "objects": {
            "c0": {
                "type": u"person",
                "name": u"carol",
                "age": 22
            }
        }
    }
]


# These SDOs have number_observed > 1; these patterns require contributions
# of several observations from several SDOs to satisfy.
@pytest.mark.parametrize("pattern", [
    "[person:age < 20] repeats 5 times",
    "[person:age < 20] repeats 2 times repeats 2 times",
    "[person:name > 'aaron'] repeats 5 times within 1 seconds",
    "([person:age < 30] and [person:name > 'aaron']) within 2 seconds repeats 3 times",
])
def test_complex_match(pattern):
    assert match(pattern, _observations)


@pytest.mark.parametrize("pattern", [
    "[person:age < 20] repeats 10 times",
    "[person:age < 20] repeats 2 times repeats 3 times"
])
def test_complex_nomatch(pattern):
    assert not match(pattern, _observations)
