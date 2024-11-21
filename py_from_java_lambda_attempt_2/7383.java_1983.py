Here is the translation of the given Java code into Python:

```Python
class SecurityDomainTag:
    def __init__(self, reader):
        self.security_domain = reader.read_int()

    @property
    def security_domain(self):
        return self._security_domain


# Example usage:
import io.BytesIO as BytesIO

reader = BytesIO(b'\x00\x01\x02\x03')  # Replace with your binary data
tag = SecurityDomainTag(reader)
print(tag.security_domain)  # Output: 3 (or the value read from the file)
```

Note that Python does not have a direct equivalent to Java's `BinaryReader` class. Instead, we use the built-in `BytesIO` class to create an in-memory binary stream and then call its methods (`read_int()`) to parse the data.

Also note that I used the `@property` decorator to implement a read-only property for the `security_domain` attribute. This is equivalent to Java's getter method, but it provides more flexibility and encapsulation in Python.