class GifDataType:
    MAGIC_87 = bytes('GI78a', 'utf-8')
    MAGIC_89 = bytes('GIF89a', 'utf-8')
    GIFMASK = b'\xff\xff\xff\xff\xff\xff'

    def __init__(self):
        self.__init__(None)

    def __init__(self, dtm=None):
        super().__init__(None, "GIF-Image", dtm)

    def get_length(self):
        return -1

    def get_length(self, buf, max_len):
        try:
            gif = GIFResource(buf)
            return gif.get_length()
        except Exception as e:
            Msg.error(self, f"Invalid GIF data at {buf.address}")
            return -1

    def can_specify_length(self):
        return False

    def clone(self, dtm=None):
        if dtm == self.data_type_manager:
            return self
        return GifDataType(dtm)

    @property
    def description(self):
        return "GIF Image stored within program"

    def get_mnemonic(self, settings):
        return "GIF"

    def get_representation(self, buf, settings, length):
        return "<GIF-Image>"

class GIFResource:
    def __init__(self, buf):
        self.buf = buf

    def get_length(self):
        # This method should be implemented
        pass

class GifDataImage(DataImage):
    def __init__(self, data):
        super().__init__()
        self.data = data

    @property
    def image_icon(self):
        return ImageIcon(self.data, "<GIF-Image>")

    @property
    def image_file_type(self):
        return "gif"

class Msg:
    @staticmethod
    def error(obj, message):
        print(f"Error: {message}")

# Usage example:

dtm = None  # DataTypeManager instance
gif_data_type = GifDataType(dtm)
