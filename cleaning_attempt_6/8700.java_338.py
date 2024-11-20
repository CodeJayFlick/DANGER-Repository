class CHMRecognizer:
    def recognize(self, bytes):
        if len(bytes) >= self.number_of_bytes_required():
            if bytes[0] == 0x49 and \
               bytes[1] == 0x54 and \
               bytes[2] == 0x53 and \
               bytes[3] == 0x46:
                return "File appears to be a Microsoft Compiled HTML (CHM) file"
        return None

    def get_priority(self):
        return 100

    def number_of_bytes_required(self):
        return 4
