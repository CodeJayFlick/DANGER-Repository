class AsciiCharSetRecognizer:
    def contains(self, c: int) -> bool:
        return ' ' <= chr(c) <= '~' or c in [0x0d, 0x0a, 0x09]
