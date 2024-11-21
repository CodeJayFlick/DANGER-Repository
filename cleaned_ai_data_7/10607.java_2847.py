import os
from urllib.parse import urlparse
from PIL import Image


class IconProvider:
    def __init__(self, icon_url):
        self.icon = None
        self.url = None
        self.temp_file_failed = False

    @property
    def is_invalid(self):
        return not bool(self.icon)

    @property
    def get_icon(self):
        return self.icon

    @property
    def get_url(self):
        if self.url:
            return self.url
        else:
            return None


    def create_temp_file(self, icon_image):
        temp_file_name = "temp.help.icon"
        try:
            with open(temp_file_name, 'wb') as f:
                f.write(icon_image)
            os.remove(f.name)  # delete the file when done
            self.url = urlparse(f.name).path
            return True
        except Exception as e:
            print("Error: Unable to write temp image")
            self.temp_file_failed = True
            return False


    def get_or_create_url(self):
        if self.url:
            return self.url

        try:
            icon_image = Image.open('icon.png')  # replace with your icon file name
            self.create_temp_file(icon_image)
            return self.url
        except Exception as e:
            print("Error: Unable to create temp image")
            default_url = "default_icon_url"
            return urlparse(default_url).path


    def test_url(self, url):
        if not url:
            return False

        try:
            parsed_path = urlparse(url).path
            return os.path.exists(parsed_path)
        except Exception as e:
            return False


# Example usage:

icon_provider = IconProvider(None)  # initialize with None for now
print(icon_provider.is_invalid)

temp_file_name = icon_provider.get_or_create_url()
if temp_file_name:
    print(f"Temp file name: {temp_file_name}")
else:
    default_icon_url = "default_icon_url"
    print(f"Default URL: {default_icon_url}")

