class GzipRecognizer:
    def recognize(self, bytes):
        if len(bytes) >= self.number_of_bytes_required():
            if bytes[0] == 31 and bytes[1] == 8:
                return "File appears to be a GZIP compressed file"
        return None

    def get_priority(self):
        return 100

    def number_of_bytes_required(self):
        return 2
