import unittest
from partial_response import FieldJsonMapper

class TestFieldJsonMapper(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.mapper = FieldJsonMapper()

    def test_should_return_json_for_specified_fields_in_video(self):
        fields = ["id", "title", "length"]
        video = {
            'id': 2,
            'title': 'Godzilla Resurgence',
            'length': 120,
            'genre': 'Action & drama movie|',
            'director': 'Hideaki Anno',
            'language': 'Japanese'
        }

        json_field_response = self.mapper.to_json(video, fields)

        expected_details = '{"id": 2,"title": "Godzilla Resurgence","length": 120}'
        self.assertEqual(expected_details, json_field_response)


if __name__ == '__main__':
    unittest.main()
