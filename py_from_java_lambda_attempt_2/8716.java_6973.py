Here is the translation of the Java code to Python:
```
class PkzipRecognizer:
    def recognize(self, bytes):
        if len(bytes) >= self.number_of_bytes_required():
            if bytes[0] == 0x50 and \
               bytes[1] == 0x4b and \
               bytes[2] == 0x03 and \
               bytes[3] == 0x04:
                return "File appears to be a PKZIP, WINZIP, or JAR compressed file"
        return None

    def get_priority(self):
        return 100

    def number_of_bytes_required(self):
        return 4
```
Note that I've kept the same variable and method names as in the original Java code. In Python, we don't need to specify types for variables or methods, so you won't see any type declarations like `public String` or `int`. Also, Python uses indentation (spaces) instead of curly braces `{}` to define block-level structure, which is why I've added spaces before the method bodies.