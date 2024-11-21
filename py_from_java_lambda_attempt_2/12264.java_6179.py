Here is the translation of the Java code to Python:
```
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
```
Note that I've omitted the `getImageIcon()` and `getImageFileType()` methods since they are abstract in Java, which means they should be implemented by subclasses. In Python, we don't have an exact equivalent of abstract classes or methods, but we can use a similar approach by defining placeholders for these methods.

Also, note that the `toString()` method has been translated to the `__str__` special method in Python, which is used to return a string representation of an object.