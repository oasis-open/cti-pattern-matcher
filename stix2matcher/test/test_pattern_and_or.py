import pytest

from stix2matcher.matcher import match

_observations = [
    {
        "type": "observed-data",
        "first_observed": "2004-10-11T21:44:58Z",
        "number_observed": 1,
        "objects": {
            "a0": {
                "type": "person",
                "name": "alice",
                "age": 10
            }
        }
    },
    {
        "type": "observed-data",
        "first_observed": "2008-05-09T01:21:58.6Z",
        "number_observed": 1,
        "objects": {
            "b0": {
                "type": "person",
                "name": "bob",
                "age": 17
            }
        }
    },
    {
        "type": "observed-data",
        "first_observed": "2006-11-03T07:42:18.96Z",
        "number_observed": 1,
        "objects": {
            "c0": {
                "type": "person",
                "name": "carol",
                "age": 22
            }
        }
    }
]


@pytest.mark.parametrize("pattern", [
    "[person:name='alice'] and [person:age>20]",
    "[person:name='alice'] or [person:name='carol']",
    "[person:name='alice'] or [person:name='zelda']",
    "[person:age>10] or [person:name='bob'] or [person:name>'amber']",
    # tests operator precedence
    "[person:age > 20] or [person:name > 'zelda'] and [person:age < 0]"
])
def test_and_or_match(pattern):
    assert match(pattern, _observations)


@pytest.mark.parametrize("pattern", [
    "[person:name='alice'] and [person:name='zelda']",
    "[person:name='mary'] or [person:name='zelda']",
    "[person:age > 70] or [person:name > 'zelda'] and [person:name MATCHES '^...?$']",
    # same as precedence test above, with parentheses to alter eval order
    "([person:age > 20] or [person:name > 'zelda']) and [person:age < 0]"
])
def test_and_or_nomatch(pattern):
    assert not match(pattern, _observations)
