Here is the equivalent Python code:

```Python
class DmgRecognizer:
    def recognize(self, bytes):
        if len(bytes) >= self.number_of_bytes_required():
            if bytes[0] == 0x47 and \
               bytes[1] == 0x4d and \
               bytes[2] == 0x49 and \
               bytes[3] == 0x32:
                return "File appears to be an Apple Disk Image file"
        return None

    def get_priority(self):
        return 100

    def number_of_bytes_required(self):
        return 4
```

Note that Python is a dynamically-typed language, so you don't need to declare the types of variables or method parameters. Also, in Python, classes are defined using the `class` keyword and methods are defined inside these classes. The equivalent of Java's `public`, `private`, etc., access modifiers do not exist in Python; instead, everything is public by default unless you use the `_` prefix for a name (which makes it "private" to that module).