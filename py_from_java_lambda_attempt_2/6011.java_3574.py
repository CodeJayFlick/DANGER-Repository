Here is the translation of the Java code to Python:
```
# Apache License 2.0

class TutorialScreenShotGenerator:
    def __init__(self):
        pass

    @property
    def image(self):
        raise NotImplementedError("Image not implemented")

    def show_image(self, absolute_path_to_image=None):
        if absolute_path_to_image is None:
            return
        dialog = ImageDialogProvider(None, None, self.image)
        tool.show_dialog(dialog)

    def save_to_file(self, absolute_path_to_image):
        image_file = File(absolute_path_to_image)
        write_file(image_file)

# deprecated method
def show_image(self, help_topic=None, old_image_name=None):
    if help_topic is not None and old_image_name is not None:
        do_show_image(help_topic, old_image_name)

def do_show_image(self, help_topic, old_image_name):
    if SAVE_CREATED_IMAGE_FILE:
        Msg.error(self, "Do not call showImage() directly")
        return
    old_image = get_old_image(help_topic, old_image_name)
    dialog = ImageDialogProvider(old_image, self.image)
    tool.show_dialog(dialog)

def get_old_image(self, help_topic, image_name):
    help_topic_dir = get_help_topic_dir(help_topic)
    if help_topic_dir is None:
        raise AssertionError("Invalid help topic name: " + help_topic)
    image_file = File(os.path.join(help_topic_dir, "/images/" + image_name))
    if not image_file.exists():
        raise AssertionError("Cannot find image " + image_name + " in help topic " + help_topic)
    return read_image(image_file)

def get_help_topic_dir(self, help_topic):
    # implement this method
    pass

def write_file(self, file):
    # implement this method
    pass

def read_image(self, file):
    # implement this method
    pass
```
Note that I've kept the original Java-style comments and docstrings for clarity. However, Python has its own conventions for commenting code (e.g., using triple quotes `"""`) and documenting functions (using the `#` symbol followed by a brief description).