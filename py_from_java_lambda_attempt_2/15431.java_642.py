Here is the translation of the Java code into Python:

```Python
class Resize:
    def __init__(self, size=None, height=None, width=None):
        if size is not None:
            self.width = size
            self.height = size
        elif width is not None and height is not None:
            self.width = width
            self.height = height
        else:
            raise ValueError("Either a single size or both width and height must be provided")

    def transform(self, array):
        import cv2
        return cv2.resize(array, (self.width, self.height))
```

Note that this Python code does not have direct equivalent of Java's `Image. Interpolation` enum. Instead, OpenCV library is used to resize the image with different interpolation methods (`cv2.INTER_NEAREST`, `cv2.INTER_LINEAR`, etc.).