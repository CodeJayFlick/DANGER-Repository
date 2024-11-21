class GenericByteSequencePattern:
    def __init__(self, bytes_sequence: list[int], action):
        self.bytes_sequence = bytes_sequence
        self.action = action

    @classmethod
    def from_bytes_and_action(cls, bytes_sequence: list[int], action):
        return cls(bytes_sequence, action)

    @classmethod
    def from_bytes_mask_and_action(cls, bytes_sequence: list[int], mask: list[int], action):
        return cls([bytes(x) for x in zip(bytes_sequence, mask)], action)


class GenericMatchAction:
    pass


# Example usage:

def my_match_action(data_type):
    print(f"Matched {data_type}")

pattern = GenericByteSequencePattern.from_bytes_and_action([0x01, 0x02], lambda data_type: my_match_action(data_type))

another_pattern = GenericByteSequencePattern.from_bytes_mask_and_action([0x03, 0x04], [0x05, 0x06], lambda data_type: my_match_action(data_type))
