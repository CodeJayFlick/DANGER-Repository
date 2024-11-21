Here is the equivalent Python code:

```Python
class ImpRecognizer:
    def recognize(self, bytes):
        if len(bytes) >= self.number_of_bytes_required():
            if bytes[0] == 0x49 and \
               bytes[1] == 0x4d and \
               bytes[2] == 0x50 and \
               bytes[3] == 0x0a:
                return "File appears to be an IMP compressed file"
        return None

    def get_priority(self):
        return 100

    def number_of_bytes_required(self):
        return 4
```

Note that Python is a dynamically-typed language, so you don't need to specify the type of variables. Also, Python uses indentation (spaces or tabs) to define block-level structure in code, unlike Java which uses curly braces `{}` for this purpose.