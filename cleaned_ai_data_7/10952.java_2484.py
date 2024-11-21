class MissingIMGFileInvalidLink(Exception):
    def __init__(self, message="Image file not in help module"):
        super().__init__(message)

def missing_img_file_invalid_link(img):
    raise MissingIMGFileInvalidLink()
