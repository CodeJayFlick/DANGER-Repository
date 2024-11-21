Here is the translation of the Java code to Python:
```
class LhaRecognizer:
    def recognize(self, bytes):
        if len(bytes) >= self.number_of_bytes_required():
            if bytes[2] == 0x2d and \
               bytes[3] == 0x6c and \
               bytes[4] == 0x68:
                return "File appears to be a LHA/LHARC compressed file"
        return None

    def get_priority(self):
        return 100

    def number_of_bytes_required(self):
        return 5
```
Note that I've kept the same variable names and method signatures as in the original Java code, but translated them directly into Python syntax.