import io.Serializable

class ExpressionValue(Serializable):
    def long_value(self, buf: bytes, offset: int) -> int:
        pass  # implement this method in your subclass

    def length(self, buf: bytes, offset: int) -> int:
        pass  # implement this method in your subclass
