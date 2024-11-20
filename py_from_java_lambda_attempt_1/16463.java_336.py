Here is the translation of the Java code to Python:

```Python
class HardState:
    def __init__(self):
        self.current_term = None
        self.vote_for = None

    @staticmethod
    def deserialize(buffer):
        res = HardState()
        res.current_term = ReadWriteIOUtils.read_long(buffer)
        is_null = buffer.get()
        if is_null == 1:
            node = Node()
            NodeSerializeUtils.deserialize(node, buffer)
            res.vote_for = node
        else:
            res.vote_for = None
        return res

    def serialize(self):
        output_stream = bytearray()
        data_output_stream = BytesIO(output_stream)

        try:
            data_output_stream.write(self.current_term.to_bytes((self.current_term.bit_length() + 7) // 8, 'big'))
            if self.vote_for is None:
                data_output_stream.write(b'\x00')
            else:
                data_output_stream.write(b'\x01')
                NodeSerializeUtils.serialize(self.vote_for, data_output_stream)
        except Exception as e:
            pass

        return bytes(output_stream)

    @property
    def current_term(self):
        return self._current_term

    @current_term.setter
    def current_term(self, value):
        self._current_term = value

    @property
    def vote_for(self):
        return self._vote_for

    @vote_for.setter
    def vote_for(self, value):
        self._vote_for = value

    def __eq__(self, other):
        if self is other:
            return True
        elif not isinstance(other, HardState):
            return False
        else:
            that = other
            return (self.current_term == that.current_term and 
                    self.vote_for == that.vote_for)

    def __hash__(self):
        return hash((self.current_term, self.vote_for))

    def __str__(self):
        return f"HardState{{'currentTerm': {self.current_term}, 'voteFor': {self.vote_for}}}"
```

Note: The ReadWriteIOUtils and NodeSerializeUtils classes are not provided in the original Java code. They seem to be utility functions for reading and writing data, respectively. In Python, you would need to implement these utilities or replace them with equivalent functionality.

Also note that this translation assumes that `Node` is a class defined elsewhere in your program, as it was in the original Java code.