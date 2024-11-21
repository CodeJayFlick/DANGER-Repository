Here is the equivalent Python code:

```Python
class EmptyPkzipRecognizer:
    def recognize(self, bytes):
        if len(bytes) >= self.number_of_bytes_required():
            if bytes[0] == 0x50 and \
               bytes[1] == 0x4b and \
               bytes[2] == 0x05 and \
               bytes[3] == 0x06:
                return "File appears to be an empty PKZIP compressed file"
        return None

    def get_priority(self):
        return 100

    def number_of_bytes_required(self):
        return 4
```

Note that Python is a dynamically-typed language, so we don't need explicit type declarations like `public String` or `int`. Also, the equivalent of Java's `implements Recognizer` would be to define an interface `Recognizer` and have this class implement it.