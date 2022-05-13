import pytest
import six

from stix2matcher.matcher import match

_stix_version = '2.1'
_observations = [
    {
        "type": "bundle",
        "id": "bundle--1e48ddd8-4614-4a51-af6d-014cec0dfa6b",
        "objects": [
            {
                "id": "observed-data--4d517ca9-e553-4b0c-b432-72740968056f",
                "type": "observed-data",
                "number_observed": 1,
                "first_observed": "1994-11-29T13:37:52Z",
                "last_observed": "1994-11-29T13:37:52Z",
                "objects": {},
                "object_refs": [
                    "person--b3cf8ecc-1196-4c69-813c-6f006da8157c"
                ],
                "spec_version": "2.1"
            },
            {
                "type": "person",
                "name": "alice",
                "id": "person--b3cf8ecc-1196-4c69-813c-6f006da8157c"
            }
        ]
    },
    {
        "type": "bundle",
        "id": "bundle--81f439bd-3aa6-4d2d-9dd0-e35a12342a69",
        "objects": [
            {
                "id": "observed-data--7d34018e-986c-4817-a2c5-21fe95284109",
                "type": "observed-data",
                "number_observed": 1,
                "first_observed": "1994-11-29T13:37:57Z",
                "last_observed": "1994-11-29T13:37:57Z",
                "objects": {},
                "object_refs": [
                    "person--08e2d542-380e-4578-86a5-460b15fea7e3"
                ],
                "spec_version": "2.1"
            },
            {
                "type": "person",
                "name": "bob",
                "id": "person--08e2d542-380e-4578-86a5-460b15fea7e3"
            }
        ]
    },
    {
        "type": "bundle",
        "id": "bundle--6a8a5b3b-c135-4792-aab0-fd17ca960d32",
        "objects": [
            {
                "id": "observed-data--52a5bab7-2cfd-40c6-a35a-b5bcb8afb11b",
                "type": "observed-data",
                "number_observed": 1,
                "first_observed": "1994-11-29T13:38:02Z",
                "last_observed": "1994-11-29T13:38:02Z",
                "objects": {},
                "object_refs": [
                    "person--799d758a-036a-4d35-8765-6a08a45b9152"
                ],
                "spec_version": "2.1"
            },
            {
                "type": "person",
                "name": "carol",
                "id": "person--799d758a-036a-4d35-8765-6a08a45b9152"
            }
        ]
    }
]


@pytest.mark.parametrize("pattern,expected_ids", [
    # match() returns the SDOs only for the first binding
    # found, so to assure results are predictable, it's best if
    # only one binding is possible for each pattern.
    ("[person:name='alice']",
     "observed-data--4d517ca9-e553-4b0c-b432-72740968056f"),
    ("[person:name='bob'] AND [person:name='carol']",
        ("observed-data--7d34018e-986c-4817-a2c5-21fe95284109",
         "observed-data--52a5bab7-2cfd-40c6-a35a-b5bcb8afb11b")),
    ("[person:name='carol'] OR [person:name>'zelda']",
     "observed-data--52a5bab7-2cfd-40c6-a35a-b5bcb8afb11b")
])
def test_matching_sdos(pattern, expected_ids):
    sdos = match(pattern, _observations, stix_version=_stix_version)
    # import pprint
    # pprint.pprint(sdos)
    sdo_ids = [sdo["objects"][0]["id"] for sdo in sdos]

    if isinstance(expected_ids, six.string_types):
        assert sdo_ids == [expected_ids]
    else:
        assert sorted(sdo_ids) == sorted(expected_ids)
