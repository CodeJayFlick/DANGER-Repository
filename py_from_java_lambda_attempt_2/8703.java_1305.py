Here is the equivalent Python code:

```Python
class CramFSRecognizer:
    def recognize(self, bytes):
        if len(bytes) >= self.number_of_bytes_required():
            if bytes[0] == 0x45 and \
               bytes[1] == 0x3d and \
               bytes[2] == 0xcd and \
               bytes[3] == 0x28:
                return "File appears to be a CramFS image file"
        return None

    def get_priority(self):
        return 100

    def number_of_bytes_required(self):
        return 4
```

Note that Python is an object-oriented language, so we define the `CramFSRecognizer` class with methods (`recognize`, `get_priority`, and `number_of_bytes_required`) rather than functions.