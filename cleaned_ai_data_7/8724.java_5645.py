class SpannedPkzipRecognizer:
    def recognize(self, bytes):
        if len(bytes) >= self.number_of_bytes_required():
            if bytes[0] == 0x50 and \
               bytes[1] == 0x4b and \
               bytes[2] == 0x07 and \
               bytes[3] == 0x08:
                return "File appears to be a spanned PKZIP compressed file"
        return None

    def get_priority(self):
        return 100

    def number_of_bytes_required(self):
        return 4
