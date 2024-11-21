Here is the translation of the given Java code into Python:

```Python
import os.path
from PIL import Image

class LoadServerIcon:
    def __init__(self):
        self.last_loaded = None

    @staticmethod
    def register_effect():
        pass  # equivalent to Skript.registerEffect in Java

    @property
    def path(self):
        return self._path

    @path.setter
    def path(self, value):
        self._path = value

    def init(self, exprs, matched_pattern, is_delayed, parse_result):
        if not os.path.exists("com.destroystokyo.paper.event.server.PaperServerListPingEvent"):
            print("The load server icon effect requires Paper 1.12.2 or newer")
            return False
        self._path = exprs[0]
        return True

    def execute(self, e):
        path_string = self.path.get_single(e)
        if not path_string:
            return
        
        try:
            image = Image.open(path_string)
            self.last_loaded = image
        except Exception as ex:
            print(ex)

    def __str__(self, e=None, debug=False):
        return f"load server icon from file {self.path}"
```

Please note that Python does not have direct equivalent of Java's `@Name`, `@Description`, etc. annotations. These are used for documentation purposes and can be achieved in Python using docstrings or other documentation tools.

Also, the given code seems to be part of a larger project (Skript) which is not available publicly. Therefore, I had to make some assumptions about how certain parts should work based on my understanding of Java and Skript's functionality.