Here is the equivalent Python code:

```Python
class UharcRecognizer:
    def recognize(self, bytes):
        if len(bytes) >= self.number_of_bytes_required():
            if (bytes[0] == 0x55 and 
                bytes[1] == 0x48 and 
                bytes[2] == 0x41 and 
                (bytes[3] in [0x04, 0x05, 0x06])):
                return "File appears to be a UHARC or WinUHA compressed file"
        return None

    def get_priority(self):
        return 100

    def number_of_bytes_required(self):
        return 4
```

Note that Python is an object-oriented language and it uses classes, objects, inheritance, polymorphism, encapsulation. The above code follows these principles to translate the Java class into a Python equivalent.