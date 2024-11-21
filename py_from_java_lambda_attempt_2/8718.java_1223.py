Here is the equivalent Python code:

```Python
class RarRecognizer:
    def recognize(self, bytes):
        if len(bytes) >= self.number_of_bytes_required():
            if bytes[0] == 0x52 and \
               bytes[1] == 0x61 and \
               bytes[2] == 0x72 and \
               bytes[3] == 0x21:
                return "File appears to be a RAR compressed file"
        return None

    def get_priority(self):
        return 100

    def number_of_bytes_required(self):
        return 4
```

Note that Python is an object-oriented language, so we define the `RarRecognizer` class with methods for recognizing files and getting priority. The equivalent Java code uses a similar approach to encapsulate data and behavior in classes.