class BinaryFilter:
    def __init__(self):
        pass

    @staticmethod
    def serialize_id():
        return 1039585564327602465

    def __init__(self, left=None, right=None):
        self.left = left
        self.right = right

    def get_left(self):
        return self.left

    def get_right(self):
        return self.right

    def __str__(self):
        if not isinstance(self.left, str) or not isinstance(self.right, str):
            raise TypeError("left and right must be strings")
        return f"({self.left}, {self.right})"

    def copy(self):
        # This method should be implemented in the subclass
        pass

    def serialize(self, output_stream):
        try:
            output_stream.write(BinaryFilter.serialize_id().to_bytes(8, 'big'))
            self.left.serialize(output_stream)
            self.right.serialize(output_stream)
        except Exception as e:
            print(f"Error: {e}")

    @classmethod
    def deserialize(cls, buffer):
        left = cls.deserialize_filter(buffer)
        right = cls.deserialize_filter(buffer)
        return BinaryFilter(left=left, right=right)

    @staticmethod
    def deserialize_filter(buffer):
        # This method should be implemented in the subclass
        pass

    def __eq__(self, other):
        if not isinstance(other, BinaryFilter):
            return False
        return self.left == other.left and self.right == other.right and type(self) == type(other)

    def __hash__(self):
        return hash((self.left, self.right))
