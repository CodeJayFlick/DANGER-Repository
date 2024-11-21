class DmgInputStream:
    def __init__(self, stream):
        self.stream = stream

    @property
    def length(self):
        return self.stream.length()

    def read(self):
        try:
            return self.stream.read()
        except Exception as e:
            raise IOError(str(e))

    def readinto(self, b):
        try:
            return self.stream.read(b)
        except Exception as e:
            raise IOError(str(e))

    def readinto(self, b, off, len):
        try:
            return self.stream.read(b, off, len)
        except Exception as e:
            raise IOError(str(e))
