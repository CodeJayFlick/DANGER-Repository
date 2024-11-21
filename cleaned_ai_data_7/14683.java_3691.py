import unittest
from unittest.mock import patch, Mock
from json import dumps

class Video:
    def __init__(self, id, title, length, description, director, language):
        self.id = id
        self.title = title
        self.length = length
        self.description = description
        self.director = director
        self.language = language


class FieldJsonMapper:
    @staticmethod
    def to_json(video, fields):
        details = {
            "id": video.id,
            "title": video.title,
            "length": video.length,
            "description": video.description,
            "director": video.director,
            "language": video.language,
        }
        return dumps({field: value for field, value in details.items() if field in fields})


class VideoResource:
    def __init__(self, field_json_mapper, videos):
        self.field_json_mapper = field_json_mapper
        self.videos = videos

    def get_details(self, video_id):
        return self.get_video(video_id).to_dict()

    def get_video(self, id):
        for k, v in self.videos.items():
            if k == id:
                return v

    def get_fields_details(self, video_id, fields):
        video = self.get_video(video_id)
        return self.field_json_mapper.to_json(video, fields)


class TestVideoResource(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.videos = {
            1: Video(1, "Avatar", 178, "epic science fiction film", "James Cameron", "English"),
            2: Video(2, "Godzilla Resurgence", 120, "Action & drama movie|", "Hideaki Anno", "Japanese"),
            3: Video(3, "Interstellar", 169, "Adventure & Sci-Fi", "Christopher Nolan", "English")
        }
        cls.resource = VideoResource(Mock(), cls.videos)

    def test_get_video_details(self):
        actual_details = self.resource.get_details(1)
        expected_details = '{"id": 1,"title": "Avatar","length": 178,"description": "epic science fiction film","director": "James Cameron","language": "English"}'
        self.assertEqual(expected_details, actual_details)

    def test_get_video_fields(self):
        fields = ["id", "title", "length"]
        expected_details = '{"id": 1,"title": "Avatar","length": 178}'
        with patch.object(FieldJsonMapper, 'to_json') as mock_to_json:
            mock_to_json.return_value = expected_details
            actual_fields_details = self.resource.get_fields_details(2, fields)
            self.assertEqual(expected_details, actual_fields_details)


if __name__ == '__main__':
    unittest.main()
