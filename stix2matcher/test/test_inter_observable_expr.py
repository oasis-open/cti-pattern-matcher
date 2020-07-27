import pytest
from stix2matcher.matcher import match

_observations = [
    {
        "type": "observed-data",
        "first_observed": "2004-10-11T21:44:58Z",
        "last_observed": "2004-10-11T21:44:58Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": u"person",
                "name": u"alice",
                "place": u"earth"
            }
        }
    },
    {
        "type": "observed-data",
        "first_observed": "2008-05-09T01:21:58.6Z",
        "last_observed": "2008-05-09T01:21:58.6Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": u"person",
                "name": u"malice",
                "place": u"moontown"
            }
        }
    },
    {
        "type": "observed-data",
        "first_observed": "2006-11-03T07:42:18.96Z",
        "last_observed": "2006-11-03T07:42:18.96Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": u"person",
                "name": u"bob",
                "city_ref": u"1"
            },
            "1": {
                "type": u"city",
                "name": u"bobtown"
            }
        }
    }
]


@pytest.mark.parametrize("pattern", [
    # same value across observables (name of person B is the same as person A, but with a leading 'm')
    "[person:name MATCHES '(?P<v1>[a-z]+)'] AND [person:name MATCHES 'm(?P<v1>[a-z]+)']",
    # same value across properties (home of person is its name plus 'town'-suffix)
    "[person:name MATCHES '(?P<v2>[a-z]+)' AND person:city_ref.name MATCHES '(?P<v2>[a-z]+)town']",
    # same value within a property (first letter of name is the same as third letter)
    "[person:name MATCHES '(?P<v3>[a-z]).(?P=v3)']",
])
def test_observation_ops_match(pattern):
    assert match(pattern, _observations)


@pytest.mark.parametrize("pattern", [
    # same value across observables (two persons with the same name)
    "[person:name MATCHES '(?P<v1>[a-z]+)'] AND [person:name MATCHES '(?P<v1>[a-z]+)']",
    # same value across properties (home of person is the same as name)
    "[person:name MATCHES '(?P<v2>[a-z]+)' AND person:city_ref.name MATCHES '(?P<v2>[a-z]+)']",
    # same value within a property (first letter of name is the same as second letter)
    "[person:name MATCHES '(?P<v3>[a-z])(?P=v3)']",
])
def test_observation_ops_nomatch(pattern):
    assert not match(pattern, _observations)
