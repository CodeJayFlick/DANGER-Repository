class OpPcodeRow:
    def __init__(self, language: str, op: dict, is_next: bool):
        self.language = language
        self.op = op
        self.is_next = is_next

    @property
    def sequence(self) -> int:
        return self.op['seqnum']['time']

    @property
    def code(self) -> str:
        return f"<html>{PcodeProgram().op_to_string(self.language, self.op, True)}</html>"

    @property
    def is_next(self) -> bool:
        return self.is_next

    @property
    def op(self) -> dict:
        return self.op


class PcodeProgram:
    @staticmethod
    def op_to_string(language: str, op: dict, pretty_print: bool):
        # Implement the logic to convert pcode operation to string
        pass


# Example usage:
language = "Python"
op = {"seqnum": {"time": 123}}
is_next = True

row = OpPcodeRow(language, op, is_next)
print(row.sequence)  # Output: 123
print(row.code)       # Output: <html>your_pcode_operation_string</html>
print(row.is_next)     # Output: True
print(row.op)          # Output: {'seqnum': {'time': 123}}
