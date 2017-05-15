import pytest

from stix2matcher.matcher import match, MatcherException

_observations = [
    {
        "type": "observed-data",
        "first_observed": "2005-10-09T21:44:58Z",
        "last_observed": "2005-10-09T21:44:58Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "null_test",
                "name": None
            }
        }
    }
]


@pytest.mark.parametrize("pattern", [
    "[null_test:name > 'alice']",
    "[null_test:name <= 'alice']",
    "[null_test:name = 'alice']",
    "[null_test:name in ('alice', 'bob', 'carol')]",
    "[null_test:name like 'alice']",
    "[null_test:name matches 'alice']",
    "[null_test:name issubset '12.23.32.12/14']",
    "[null_test:name issuperset '12.23.32.12/14']"
])
def test_null_json(pattern):
    assert not match(pattern, _observations)


@pytest.mark.parametrize("pattern", [
    "[null_test:name != 'alice']"
])
def test_notequal_null_json(pattern):
    assert match(pattern, _observations)


@pytest.mark.parametrize("pattern", [
    "[null_test:name = null]",
    "[null_test:name in (null, null, null)]",
    "[null_test:name like null]",
    "[null_test:name matches null]",
    "[null_test:name issubset null]",
    "[null_test:name issuperset null]"
])
def test_null_pattern(pattern):
    with pytest.raises(MatcherException):
        match(pattern, _observations)
