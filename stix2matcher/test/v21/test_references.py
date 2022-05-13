import pytest

from stix2matcher.matcher import match

_stix_version = '2.1'
_observations = [
    {
        "type": "bundle",
        "id": "bundle--d71c4cb2-7dbe-4f51-a4a0-7956ca9ffcb0",
        "objects": [
            {
                "id": "observed-data--8c8937c4-3fa6-4035-9ade-481a95461140",
                "type": "observed-data",
                "number_observed": 1,
                "first_observed": "1984-06-26T13:53:04Z",
                "last_observed": "1984-06-26T13:53:04Z",
                "objects": {},
                "object_refs": [
                    "person--34e341a3-3e90-45e5-8b0f-aef8042e3e90",
                    "person--3fa2f82d-dd0f-4411-a221-7c75312b01bb",
                    "person--9163614b-ba54-460b-aec2-9c555b1431c4"
                ],
                "spec_version": "2.1"
            },
            {
                "type": "person",
                "name": "alice",
                "knows_ref": "person--3fa2f82d-dd0f-4411-a221-7c75312b01bb",
                "id": "person--34e341a3-3e90-45e5-8b0f-aef8042e3e90"
            },
            {
                "type": "person",
                "name": "bob",
                "knows_refs": [
                    "person--34e341a3-3e90-45e5-8b0f-aef8042e3e90",
                    "person--9163614b-ba54-460b-aec2-9c555b1431c4"
                ],
                "id": "person--3fa2f82d-dd0f-4411-a221-7c75312b01bb"
            },
            {
                "type": "person",
                "name": "carol",
                "knows_refs": [
                    "person--34e341a3-3e90-45e5-8b0f-aef8042e3e90",
                    "person--3fa2f82d-dd0f-4411-a221-7c75312b01bb",
                    "person--9163614b-ba54-460b-aec2-9c555b1431c4"
                ],
                "id": "person--9163614b-ba54-460b-aec2-9c555b1431c4"
            }
        ]
    }
]



