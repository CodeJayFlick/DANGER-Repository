class CompressionTypeNotSupportedException(Exception):
    def __init__(self, codec_class=None, message="codec not supported"):
        super().__init__(f"{message}: {str(codec_class)}" if codec_class else message)
        self.codec_class = codec_class

    @property
    def codec_class(self):
        return self._codec_class

compression_type_not_supported_exception = CompressionTypeNotSupportedException
