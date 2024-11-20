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
