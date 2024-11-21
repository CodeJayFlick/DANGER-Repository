Here is the translation of the Java code to Python:
```
class PakArcRecognizer:
    def recognize(self, bytes):
        if len(bytes) >= self.number_of_bytes_required():
            if bytes[0] == 26 and (bytes[1] & 240) == 0:
                return "File appears to be a PAK or ARC compressed file"
        return None

    def get_priority(self):
        return 100

    def number_of_bytes_required(self):
        return 2
```
Note that I've used the same variable names as in the original Java code, but with Python's conventions (e.g., `recognize` instead of `public String recognize`, etc.).