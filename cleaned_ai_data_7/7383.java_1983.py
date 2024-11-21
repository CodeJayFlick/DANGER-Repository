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
