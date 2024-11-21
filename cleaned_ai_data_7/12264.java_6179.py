import io

class DataImage:
    def __init__(self):
        self.description = None

    def get_image_icon(self):
        # Note: This method should return an image object in Python
        pass  # Implement this method

    def get_image_file_type(self):
        # Note: This method should return a string representing the file type (e.g. "png", "gif")
        pass  # Implement this method

    def set_description(self, description):
        self.description = description

    def __str__(self):
        if self.description is not None:
            return self.description
        else:
            return f"DataImage@{hex(id(self))}"
