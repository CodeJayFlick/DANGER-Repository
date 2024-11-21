class Bzip2Recognizer:
    MAGIC_BYTES = 0x5a42

    def recognize(self, bytes):
        if len(bytes) >= self.number_of_bytes_required():
            if bytes[0] == 0x42 and \
               bytes[1] == 0x5a and \
               bytes[2] == 0x68:
                return "File appears to be a BZIP2 compressed file"
        return None

    def get_priority(self):
        return 100

    def number_of_bytes_required(self):
        return 3
