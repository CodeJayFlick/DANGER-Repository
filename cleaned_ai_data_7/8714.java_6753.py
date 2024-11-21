class MSWIMRecognizer:
    def recognize(self, bytes):
        if len(bytes) >= self.number_of_bytes_required():
            if (bytes[0] == 0x4d and 
                bytes[1] == 0x53 and 
                bytes[2] == 0x57 and 
                bytes[3] == 0x49 and 
                bytes[4] == 0x4d and 
                bytes[5] == 0x00 and 
                bytes[6] == 0x00):
                return "File appears to be a Windows Imaging Format (WIM) file"
        return None

    def get_priority(self):
        return 100

    def number_of_bytes_required(self):
        return 7
