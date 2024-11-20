class LldbModelTargetStackFrameRegister:
    def __init__(self):
        pass

    def get_bit_length(self) -> int:
        # This method should be implemented in your subclass.
        raise NotImplementedError("get_bit_length must be implemented")

    def get_register(self) -> bytes:
        # This method should be implemented in your subclass.
        raise NotImplementedError("get_register must be implemented")

    def get_bytes(self) -> bytearray:
        val = self.get_cached_attributes().get('VALUE_ATTRIBUTE_NAME')
        value = int(val, 16)
        return ConversionUtils.bigIntegerToBytes(16, value).tobytes()
