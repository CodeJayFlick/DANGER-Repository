import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
LOGGER = logging.getLogger(__name__)

class Video:
    def __init__(self, id, title, length, description, director, language):
        self.id = id
        self.title = title
        self.length = length
        self.description = description
        self.director = director
        self.language = language

videos = {
    1: Video(1, "Avatar", 178, "epic science fiction film", "James Cameron", "English"),
    2: Video(2, "Godzilla Resurgence", 120, "Action & drama movie|", "Hideaki Anno", "Japanese"),
    3: Video(3, "Interstellar", 169, "Adventure & Sci-Fi", "Christopher Nolan", "English")
}

class VideoResource:
    def __init__(self, field_json_mapper, videos):
        self.field_json_mapper = field_json_mapper
        self.videos = videos

    def get_details(self, video_id, *fields):
        if fields:
            return {field: getattr(self.videos[video_id], field) for field in fields}
        else:
            return dict((k, v.__dict__) for k, v in self.videos.items() if k == video_id)

def main():
    LOGGER.info("Retrieving full response from server:-")
    LOGGER.info("Get all video information:")
    details = VideoResource(None, videos).get_details(1)
    LOGGER.info(details)

    LOGGER.info("----------------------------------------------------------")

    LOGGER.info("Retrieving partial response from server:-")
    LOGGER.info("Get video @id, @title, @director:")
    specific_fields_details = VideoResource(None, videos).get_details(3, "id", "title", "director")
    LOGGER.info(specific_fields_details)

    LOGGER.info("Get video @id, @length:")
    video_length = VideoResource(None, videos).get_details(3, "id", "length")
    LOGGER.info(video_length)

if __name__ == "__main__":
    main()
