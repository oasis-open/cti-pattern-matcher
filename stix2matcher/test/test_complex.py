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
    "[person:age < 20] REPEATS 5 TIMES",
    "[person:age < 20] REPEATS 2 TIMES REPEATS 2 TIMES",
    "[person:name > 'aaron'] REPEATS 5 TIMES WITHIN 1 SECONDS",
    "([person:age < 30] AND [person:name > 'aaron']) WITHIN 2 SECONDS REPEATS 3 TIMES",
])
def test_complex_match(pattern):
    assert match(pattern, _observations)


@pytest.mark.parametrize("pattern", [
    "[person:age < 20] REPEATS 10 TIMES",
    "[person:age < 20] REPEATS 2 TIMES REPEATS 3 TIMES"
])
def test_complex_nomatch(pattern):
    assert not match(pattern, _observations)
