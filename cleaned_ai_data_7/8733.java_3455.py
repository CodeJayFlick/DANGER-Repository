class VHDRecognizer:
    def recognize(self, bytes):
        if len(bytes) >= self.number_of_bytes_required():
            if (bytes[0] == 99 and 
                bytes[1] == 111 and 
                bytes[2] == 110 and 
                bytes[3] == 101 and 
                bytes[4] == 99 and 
                bytes[5] == 116 and 
                bytes[6] == 105 and 
                bytes[7] == 122):
                return "File appears to be a Connectix VHD image"
        return None

    def get_priority(self):
        return 100

    def number_of_bytes_required(self):
        return 8
