Here is the translation of the Java code to Python:
```
class SevenZipRecognizer:
    def recognize(self, bytes):
        if len(bytes) >= self.number_of_bytes_required():
            if (bytes[0] == 37 and
                bytes[1] == 122 and
                bytes[2] == 188 and
                bytes[3] == 175 and
                bytes[4] == 39 and
                bytes[5] == 28):
                return "File appears to be a 7-ZIP compressed file"
        return None

    def get_priority(self):
        return 100

    def number_of_bytes_required(self):
        return 6
```
Note that I've kept the same variable names and method signatures as in the original Java code, but translated them directly into Python.