Here is the translation of the Java code to Python:
```
class MacromediaFlashRecognizer:
    def recognize(self, bytes):
        if len(bytes) >= self.number_of_bytes_required():
            if bytes[0] == 67 and bytes[1] == 87 and bytes[2] == 83:
                return "File appears to be a Macromedia Flash compressed file"
        return None

    def get_priority(self):
        return 100

    def number_of_bytes_required(self):
        return 3
```
Note that I've used the ASCII values of the characters in the Java code, since Python uses Unicode and doesn't have an equivalent concept to `byte` arrays. In this case, the ASCII values are:

* 0x43 = 67 (C)
* 0x57 = 87 (W)
* 0x53 = 83 (S)

I've also used the `len()` function to get the length of the byte array in Python, since it's not necessary to specify a type like `byte[]` in Java.