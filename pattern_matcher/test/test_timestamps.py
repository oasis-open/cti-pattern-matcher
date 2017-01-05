
import pytest
import datetime
import dateutil.tz

from pattern_matcher.matcher import match, MatcherException

_observations = [
    {
        "type": "cybox-container",
        "objects": {
            "0": {
                "type": "event",
                "good_ts": "2010-05-21T13:21:43Z",
                "good_ts_frac": "2010-05-21T13:21:43.1234Z",
                "bad_ts": [
                    "2010-05-21T13:21:43",
                    "2010-05-21T13:21:43z",
                    "2010-05-21t13:21:43Z",
                    "2010/05/21T13:21:43Z",
                    "2010-05-21T13:21:99Z",
                    "2010-05-21T13:21Z"
                ]
            }
        }
    }
]

_timestamps = [datetime.datetime.now(dateutil.tz.tzutc())] * len(_observations)


@pytest.mark.parametrize("pattern", [
    "[event:good_ts = t'2010-05-21T13:21:43Z']",
    "[event:good_ts != t'1974-11-05T05:31:11Z']",
    "[event:good_ts > t'1974-11-05T05:31:11Z']",
    "[event:good_ts < t'3012-08-17T17:43:55Z']",
    "[event:good_ts_frac = t'2010-05-21T13:21:43.1234Z']"
])
def test_ts_match(pattern):
    assert match(pattern, _observations, _timestamps)


@pytest.mark.parametrize("pattern", [
    # Same as above with operators reversed.
    "[event:good_ts != t'2010-05-21T13:21:43Z']",
    "[event:good_ts = t'1974-11-05T05:31:11Z']",
    "[event:good_ts <= t'1974-11-05T05:31:11Z']",
    "[event:good_ts >= t'3012-08-17T17:43:55Z']",
    "[event:good_ts_frac != t'2010-05-21T13:21:43.1234Z']"
])
def test_ts_nomatch(pattern):
    assert not match(pattern, _observations, _timestamps)


@pytest.mark.parametrize("pattern", [
    "[event:good_ts = t'2010-05-21T13:21:43']",
    "[event:good_ts = t'2010-05-21T13:21:43z']",
    "[event:good_ts = t'2010-05-21t13:21:43Z']",
    "[event:good_ts = t'2010/05/21T13:21:43Z']",
    "[event:good_ts = t'2010-05-21T13:21:99Z']",
    "[event:good_ts = t'2010-05-21T13:21Z']",
])
def test_ts_pattern_error(pattern):
    with pytest.raises(MatcherException):
        match(pattern, _observations, _timestamps)


@pytest.mark.parametrize("pattern", [
    # auto-generate simple tests for all the bad timestamps
    "[event:bad_ts[{}] = t'1996-07-11T09:17:10Z']".format(i)
    for i in range(len(_observations[0]["objects"]["0"]["bad_ts"]))
])
def test_ts_json_error(pattern):
    with pytest.raises(MatcherException):
        match(pattern, _observations, _timestamps)
