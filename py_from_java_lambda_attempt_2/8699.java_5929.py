Here is the equivalent Python code:

```Python
class CabarcRecognizer:
    def recognize(self, bytes):
        if len(bytes) >= self.number_of_bytes_required():
            if bytes[0] == 0x4d and \
               bytes[1] == 0x53 and \
               bytes[2] == 0x43 and \
               bytes[3] == 0x46:
                return "File appears to be a CABARC compressed file"
        return None

    def get_priority(self):
        return 100

    def number_of_bytes_required(self):
        return 4
```

Note that Python is an object-oriented language, so we define the `CabarcRecognizer` class with methods for recognizing files and getting priority. The equivalent of Java's `public` access modifier in Python is not explicitly needed as all members are public by default.