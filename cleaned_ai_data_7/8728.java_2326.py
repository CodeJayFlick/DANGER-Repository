class SzipRecognizer:
    def recognize(self, bytes):
        if len(bytes) >= self.number_of_bytes_required():
            if (bytes[0] == 0x53 and
                bytes[1] == 0x5A and
                bytes[2] == 0x0a and
                bytes[3] == 0x04):
                return "File appears to be a szip compressed file"
        return None

    def get_priority(self):
        return 100

    def number_of_bytes_required(self):
        return 4


# Example usage:
recognizer = SzipRecognizer()
result = recognizer.recognize(b'\x53\x5A\x0a\x04')
print(result)  # Output: "File appears to be a szip compressed file"
