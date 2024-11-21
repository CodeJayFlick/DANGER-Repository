Here is the equivalent Python code:

```Python
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
```

Note that I've used the `unittest` module to write unit tests in Python. The equivalent of Java's JUnit is Pytest for Python but since you asked specifically for translating it into Python using only Python and not any other testing framework, I have written this code with `unittest`.