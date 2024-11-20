class SqzRecognizer:
    def recognize(self, bytes):
        if len(bytes) >= self.number_of_bytes_required():
            if (bytes[0] == 0x48 and 
                bytes[1] == 0x4c and 
                bytes[2] == 0x53 and 
                bytes[3] == 0x51 and 
                bytes[4] == 0x5a and 
                bytes[5] == 0x31):
                return "File appears to be a SQZ compressed file"
        return None

    def get_priority(self):
        return 100

    def number_of_bytes_required(self):
        return 6
