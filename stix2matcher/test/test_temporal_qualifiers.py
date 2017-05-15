import pytest

from stix2matcher.matcher import match, MatcherException

# I'll specially test some critical internal time-interval related code,
# since it's easier to test it separately than create lots of SDOs and
# patterns.
from stix2matcher.matcher import (_overlap, _OVERLAP_NONE, _OVERLAP,
                                  _OVERLAP_TOUCH_INNER, _OVERLAP_TOUCH_OUTER,
                                  _OVERLAP_TOUCH_POINT)
from stix2matcher.matcher import _timestamp_intervals_within


_observations = [
    {
        "type": "observed-data",
        "first_observed": "1994-11-29T13:37:52Z",
        "last_observed": "1994-11-29T13:37:52Z",
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
        "last_observed": "1994-11-29T13:37:57Z",
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
        "last_observed": "1994-11-29T13:38:02Z",
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


# The below tests use ints instead of timestamps.  The code is generic enough
# and it's much easier to test with simple ints.

@pytest.mark.parametrize("min1,max1,min2,max2,expected_overlap", [
    (1, 1, 1, 1, _OVERLAP_TOUCH_POINT),
    (1, 1, 1, 2, _OVERLAP_TOUCH_INNER),
    (1, 2, 1, 1, _OVERLAP_TOUCH_OUTER),
    (1, 2, 2, 2, _OVERLAP_TOUCH_INNER),
    (2, 2, 1, 2, _OVERLAP_TOUCH_OUTER),
    (1, 2, 2, 3, _OVERLAP_TOUCH_INNER),
    (2, 3, 1, 2, _OVERLAP_TOUCH_OUTER),
    (1, 2, 1, 3, _OVERLAP),
    (1, 3, 1, 2, _OVERLAP),
    (1, 3, 2, 3, _OVERLAP),
    (2, 3, 1, 3, _OVERLAP),
    (1, 3, 2, 4, _OVERLAP),
    (2, 4, 1, 3, _OVERLAP),
    (1, 4, 2, 3, _OVERLAP),
    (2, 3, 1, 4, _OVERLAP),
    (1, 3, 2, 2, _OVERLAP),
    (2, 2, 1, 3, _OVERLAP),
    (1, 2, 3, 4, _OVERLAP_NONE),
    (3, 4, 1, 2, _OVERLAP_NONE)
])
def test_overlap(min1, max1, min2, max2, expected_overlap):
    assert _overlap(min1, max1, min2, max2) == expected_overlap


@pytest.mark.parametrize("intervals,duration", [
    (((1, 1), (1, 1)), 0),
    (((1, 1), (1, 1)), 1),
    (((1, 1), (1, 2)), 1),
    (((1, 2), (3, 4)), 1),
    (((1, 4), (2, 3)), 1),
    (((1, 3), (2, 4)), 1),
    (((1, 2), (3, 4), (5, 6)), 4),
    (((1, 4), (2, 3), (4, 5)), 1),
    (((1, 2), (2, 3), (4, 5)), 2),
    (((1, 2), (2, 3), (4, 5)), 3)
])
def test_intervals_within_match(intervals, duration):
    assert _timestamp_intervals_within(intervals, duration)


@pytest.mark.parametrize("intervals,duration", [
    (((1, 2), (3, 4)), 0),
    (((1, 2), (4, 5)), 1),
    (((1, 2), (3, 4), (5, 6)), 2),
    (((1, 5), (1, 2), (4, 5)), 1),
    (((1, 2), (1, 3), (1, 4), (4, 5)), 1)
])
def test_intervals_within_nomatch(intervals, duration):
    assert not _timestamp_intervals_within(intervals, duration)


# For these tests, instead of keeping the data fixed and changing the
# pattern, we adjust timestamps in the data to further exercise temporal
# operations, and keep the pattern mostly fixed.
_1 = "2000-01-01T00:00:00Z"
_2 = "2000-01-01T00:00:01Z"
_3 = "2000-01-01T00:00:02Z"
_4 = "2000-01-01T00:00:03Z"
_5 = "2000-01-01T00:00:04Z"


@pytest.mark.parametrize("interval1,interval2,duration", [
    ((_1, _1), (_1, _1), 1),
    ((_1, _1), (_1, _2), 1),
    ((_1, _1), (_1, _2), 2),
    ((_1, _2), (_2, _3), 1),
    ((_1, _2), (_3, _4), 1),
    ((_1, _4), (_2, _3), 1),
    ((_1, _3), (_2, _4), 1),
    ((_1, _2), (_4, _5), 2),
])
def test_within_match(interval1, interval2, duration):

    _observations[0]["first_observed"] = interval1[0]
    _observations[0]["last_observed"] = interval1[1]

    _observations[1]["first_observed"] = interval2[0]
    _observations[1]["last_observed"] = interval2[1]

    pattern = "([person:name='alice'] and [person:name='bob']) " \
              "within {0} seconds".format(duration)
    assert match(pattern, _observations)


@pytest.mark.parametrize("interval1,interval2,duration", [
    ((_1, _2), (_4, _5), 1),
    ((_1, _1), (_4, _5), 2),
    ((_1, _2), (_5, _5), 2),
])
def test_within_nomatch(interval1, interval2, duration):

    _observations[0]["first_observed"] = interval1[0]
    _observations[0]["last_observed"] = interval1[1]

    _observations[1]["first_observed"] = interval2[0]
    _observations[1]["last_observed"] = interval2[1]

    pattern = "([person:name='alice'] and [person:name='bob']) " \
              "within {0} seconds".format(duration)
    assert not match(pattern, _observations)
