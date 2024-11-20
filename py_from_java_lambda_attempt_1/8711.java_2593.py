Here is the equivalent Python code:

```Python
class JarRecognizer:
    def recognize(self, bytes):
        if len(bytes) >= self.number_of_bytes_required():
            if bytes[0] == 0x50 and \
               bytes[1] == 0x4b and \
               bytes[2] == 0x03 and \
               bytes[3] == 0x04:
                return "File appears to be a JAR compressed file"
        return None

    def get_priority(self):
        return 100

    def number_of_bytes_required(self):
        return 4
```

Note that Python is an object-oriented language, so we define the `JarRecognizer` class with methods for recognizing and getting priority. The `recognize` method checks if the given bytes meet certain conditions (length and specific byte values) to determine whether they are a JAR file or not.