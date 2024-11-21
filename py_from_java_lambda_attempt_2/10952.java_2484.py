Here is the translation of the Java code to Python:
```
class MissingIMGFileInvalidLink(Exception):
    def __init__(self, message="Image file not in help module"):
        super().__init__(message)

def missing_img_file_invalid_link(img):
    raise MissingIMGFileInvalidLink()
```
Note that I've translated the `public class` declaration to a Python `class`, and removed the Java-specific keywords like `extends`. The constructor (`__init__`) is similar in both languages, but in Python we don't need to specify the type of the variables.