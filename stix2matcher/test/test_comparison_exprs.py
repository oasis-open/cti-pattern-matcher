import pytest
from stix2matcher.matcher import match

_observations = [
    {
        "type": "observed-data",
        "number_observed": 1,
        "first_observed": "2004-11-26T11:42:29Z",
        "last_observed": "2004-11-26T11:42:29Z",
        "objects": {
            "0": {
                "type": u"person",
                "name": u"alice",
                "age": 10
            },
            "1": {
                "type": u"person",
                "name": u"bob",
                "age": 15
            }
        }
    }
]


@pytest.mark.parametrize("pattern", [
    "[person:name = 'alice' and person:age < 20]",
    "[person:name = 'alice' or person:age > 20]",
    "[person:name = 'alice' or person:age > 1000 and person:age < 0]",
    "[(person:name = 'carol' or person:name = 'bob') and person:age > 10]",
    "[(person:name = 'darlene' or person:name = 'carol') and person:age < 0 or person:age > 5]"
])
def test_comparison_and_or_match(pattern):
    assert match(pattern, _observations)


@pytest.mark.parametrize("pattern", [
    "[person:name = 'alice' and person:age > 10]",
    "[person:name = 'carol' or person:age > 20]",
    "[(person:age = 'alice' or person:age > 1000) and person:age < 0]",
    "[(person:name = 'darlene' or person:name = 'carol') and (person:age < 0 or person:age > 5)]"
])
def test_comparison_and_or_nomatch(pattern):
    assert not match(pattern, _observations)
