import pytest
from stix2matcher.matcher import MatcherException, match

_observations = [
    {
        "type": "observed-data",
        "number_observed": 1,
        "first_observed": "2014-04-19T06:51:26Z",
        "last_observed": "2014-04-19T06:51:26Z",
        "objects": {
            "0": {
                "type": "test",
                "int": 5,
                "float": 12.658,
                "float_int": 12.0,
                "bool": True,
                "string": u"hello",
                "ip": u"11.22.33.44",
                "cidr": u"11.22.33.44/20"
            }
        }
    }
]


@pytest.mark.parametrize("pattern", [
    "[test:int = 5]",
    "[test:int not != 5]",
    "[test:int > 3]",
    "[test:int not < 3]",
    "[test:int < 12]",
    "[test:int > 4.9]",
    "[test:int < 5.1]",
    "[test:int >= 5]",
    "[test:int not < 5]",
    "[test:int <= 5]",
    "[test:int != false]",
    "[test:int != true]",
    "[test:int not = true]",
    "[test:int != 'world']",
    "[test:int != h'010203']",
    "[test:int != b'AQIDBA==']",
    "[test:int != t'1965-07-19T22:41:38Z']",
    "[test:int in (-4, 5, 6)]",
    "[test:int in (-4, 5, 6.6)]",
    "[test:int not in ('a', 'b', 'c')]",
    "[test:int not matches 'l+']",
    "[test:int not like 'he%']",
])
def test_basic_ops_int_match(pattern):
    assert match(pattern, _observations)


@pytest.mark.parametrize("pattern", [
    "[test:int not = 5]",
    "[test:int not != 8]",
    "[test:int > 8]",
    "[test:int < 2]",
    "[test:int > 5.1]",
    "[test:int < 4.9]",
    "[test:int = false]",
    "[test:int = true]",
    "[test:int = 'world']",
    "[test:int = h'010203']",
    "[test:int > h'010203']",
    "[test:int = b'AQIDBA==']",
    "[test:int < b'AQIDBA==']",
    "[test:int = t'1965-07-19T22:41:38Z']",
    "[test:int > t'1965-07-19T22:41:38Z']",
    "[test:int like 'he%']",
    "[test:int matches 'l+']",
    "[test:int not in (-4, 5, 6)]",
    "[test:int not in (-4, 5, 6.6)]",
    "[test:int in ('a', 'b', 'c')]"
])
def test_basic_ops_int_nomatch(pattern):
    assert not match(pattern, _observations)


@pytest.mark.parametrize("pattern", [
    "[test:float = 12.658]",
    "[test:float not != 12.658]",
    "[test:float > 3]",
    "[test:float not < 3]",
    "[test:float < 22]",
    "[test:float > 12.65799]",
    "[test:float < 12.65801]",
    "[test:float >= 12.658]",
    "[test:float <= 12.658]",
    "[test:float != false]",
    "[test:float != true]",
    "[test:float != 'world']",
    "[test:float != h'010203']",
    "[test:float != b'AQIDBA==']",
    "[test:float != t'1965-07-19T22:41:38Z']",
    "[test:float in (-4.21, 12.658, 964.321)]",
    "[test:float_int in (11, 12, 13)]",
    "[test:float_int in (11.1, 12, 13)]",
    "[test:float not in ('a', 'b', 'c')]",
    "[test:float not matches 'l+']",
    "[test:float not like 'he%']",
])
def test_basic_ops_float_match(pattern):
    assert match(pattern, _observations)


@pytest.mark.parametrize("pattern", [
    "[test:float not = 12.658]",
    "[test:float != 12.658]",
    "[test:float > 22]",
    "[test:float < 3]",
    "[test:float > 12.65801]",
    "[test:float < 12.65799]",
    "[test:float = false]",
    "[test:float = true]",
    "[test:float = 'world']",
    "[test:float not != 'world']",
    "[test:float = h'010203']",
    "[test:float > h'010203']",
    "[test:float = b'AQIDBA==']",
    "[test:float < b'AQIDBA==']",
    "[test:float = t'1965-07-19T22:41:38Z']",
    "[test:float > t'1965-07-19T22:41:38Z']",
    "[test:float like 'he%']",
    "[test:float matches 'l+']",
    "[test:float not in (-4.21, 12.658, 964.321)]",
    "[test:float_int not in (11, 12, 13)]",
    "[test:float_int not in (11.1, 12, 13)]",
    "[test:float in ('a', 'b', 'c')]"
])
def test_basic_ops_float_nomatch(pattern):
    assert not match(pattern, _observations)


@pytest.mark.parametrize("pattern", [
    "[test:bool != 1]",
    "[test:bool != 32.567]",
    "[test:bool = true]",
    "[test:bool not != true]",
    "[test:bool != false]",
    "[test:bool not = false]",
    "[test:bool != 'world']",
    "[test:bool != h'010203']",
    "[test:bool != b'AQIDBA==']",
    "[test:bool != t'1965-07-19T22:41:38Z']",
    "[test:bool in (false, true, false)]",
    "[test:bool not in ('a', 'b', 'c')]",
    "[test:bool not matches 'l+']",
    "[test:bool not like 'he%']",
])
def test_basic_ops_bool_match(pattern):
    assert match(pattern, _observations)


@pytest.mark.parametrize("pattern", [
    "[test:bool = 1]",
    "[test:bool = 32.567]",
    "[test:bool != true]",
    "[test:bool not = true]",
    "[test:bool = false]",
    "[test:bool not != false]",
    "[test:bool = 'world']",
    "[test:bool = h'010203']",
    "[test:bool = b'AQIDBA==']",
    "[test:bool = t'1965-07-19T22:41:38Z']",
    "[test:bool like 'he%']",
    "[test:bool matches 'l+']",
    "[test:bool not in (false, true, false)]",
    "[test:bool in ('a', 'b', 'c')]"
])
def test_basic_ops_bool_nomatch(pattern):
    assert not match(pattern, _observations)


@pytest.mark.parametrize("pattern", [
    "[test:string != 1]",
    "[test:string != 32.567]",
    "[test:string != true]",
    "[test:string != false]",
    "[test:string = 'hello']",
    "[test:string not != 'hello']",
    "[test:string != 'world']",
    "[test:string not = 'world']",
    "[test:string > 'alice']",
    "[test:string < 'zelda']",
    "[test:string >= 'hello']",
    "[test:string <= 'hello']",
    "[test:string != h'010203']",
    "[test:string != b'AQIDBA==']",
    "[test:string like 'he%']",
    "[test:string like 'he__o']",
    "[test:string matches 'l+']",
    "[test:string matches '.lo$']",
    "[test:string in ('goodbye', 'hello', 'world')]",
    "[test:string not in (1, 2, 3)]"
])
def test_basic_ops_string_match(pattern):
    assert match(pattern, _observations)


@pytest.mark.parametrize("pattern", [
    "[test:string = 1]",
    "[test:string = 32.567]",
    "[test:string = true]",
    "[test:string = false]",
    "[test:string != 'hello']",
    "[test:string not = 'hello']",
    "[test:string = 'world']",
    "[test:string not != 'world']",
    "[test:string < 'alice']",
    "[test:string > 'zelda']",
    "[test:string <= 'alice']",
    "[test:string >= 'zelda']",
    "[test:string = h'010203']",
    "[test:string = b'AQIDBA==']",
    "[test:string not like 'he%']",
    "[test:string not like 'he__o']",
    "[test:string not matches 'l+']",
    "[test:string not matches '.lo$']",
    "[test:string not in ('goodbye', 'hello', 'world')]",
    "[test:string in (1, 2, 3)]"
])
def test_basic_ops_string_nomatch(pattern):
    assert not match(pattern, _observations)


@pytest.mark.parametrize("pattern", [
    # These are errors because a timestamp literal is used in the pattern,
    # which causes the matcher to try to interpret the JSON value as a
    # timestamp as well.  If this merely caused a false (for '=') or true
    # (for '!=') result, then timestamp formatting errors in the JSON would
    # silently slip through, causing potential false negatives.  It's
    # perhaps safer to assume in this situation that a string JSON value was
    # really intended to be a timestamp, and error out if it's incorrectly
    # formatted.
    "[test:string = t'1965-07-19T22:41:38Z']",
    "[test:string != t'1965-07-19T22:41:38Z']",
    "[test:string > t'1965-07-19T22:41:38Z']",
])
def test_basic_ops_string_err(pattern):
    with pytest.raises(MatcherException):
        match(pattern, _observations)


@pytest.mark.parametrize("pattern", [
    "[test:ip issubset '11.22.41.123/20']",
    "[test:ip not issubset '11.22.123.41/20']",
    "[test:cidr issuperset '11.22.41.123']",
    "[test:cidr issuperset '11.22.41.123/29']",
    "[test:cidr not issuperset '11.22.33.44/13']",
    "[test:cidr not issuperset '11.22.123.41/29']",
    "[test:int not issuperset '11.22.33.44']",
    "[test:int not issubset '11.22.33.44']",
    "[test:float not issuperset '11.22.33.44']",
    "[test:float not issubset '11.22.33.44']",
    "[test:bool not issuperset '11.22.33.44']",
    "[test:bool not issubset '11.22.33.44']",
])
def test_basic_ops_ip_match(pattern):
    assert match(pattern, _observations)


@pytest.mark.parametrize("pattern", [
    "[test:ip not issubset '11.22.41.123/20']",
    "[test:ip issubset '11.22.123.41/20']",
    "[test:cidr not issuperset '11.22.41.123']",
    "[test:cidr not issuperset '11.22.41.123/29']",
    "[test:cidr issuperset '11.22.33.44/13']",
    "[test:cidr issuperset '11.22.123.41/29']",
    "[test:int issuperset '11.22.33.44']",
    "[test:int issubset '11.22.33.44']",
    "[test:float issuperset '11.22.33.44']",
    "[test:float issubset '11.22.33.44']",
    "[test:bool issuperset '11.22.33.44']",
    "[test:bool issubset '11.22.33.44']",
])
def test_basic_ops_ip_nomatch(pattern):
    assert not match(pattern, _observations)


@pytest.mark.parametrize("pattern", [
    "[test:string not in ()]"
])
def test_basic_ops_emptyset_match(pattern):
    assert match(pattern, _observations)


@pytest.mark.parametrize("pattern", [
    "[test:string in ()]"
])
def test_basic_ops_emptyset_nomatch(pattern):
    assert not match(pattern, _observations)


@pytest.mark.parametrize("pattern", [
    # Sets are required to contain elements of a single type.
    "[test:string in (1, true)]",
    "[test:string in (1, 2.2, true)]",
    "[test:string in (1.1, 2.2, true)]",
])
def test_basic_ops_set_err(pattern):
    with pytest.raises(MatcherException):
        match(pattern, _observations)
