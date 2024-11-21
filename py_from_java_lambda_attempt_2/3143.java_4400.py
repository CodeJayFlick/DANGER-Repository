Here is the translation of the given Java code into Python:

```Python
class AppendCommentCmd:
    def __init__(self, address: int, comment_type: int, comment: str, separator: str):
        self.address = address
        self.comment_type = comment_type
        self.comment = comment
        self.separator = separator
        self.cmd_name = "Append Comment"
        self.message = ""

    @property
    def name(self) -> str:
        return self.cmd_name

    def apply_to(self, obj: dict):
        program = Program(obj)
        cu = self.get_code_unit(program)
        if cu is None:
            self.message = f"No Instruction or Data found for address {self.address}. Is this address valid?"
            return False
        previous_comment = cu.comment_type
        new_comment = f"{previous_comment}{self.separator}{self.comment}" if previous_comment else self.comment
        cu.set_comment(self.comment_type, new_comment)
        return True

    def get_code_unit(self, program: dict) -> dict:
        listing = program.get("listing")
        cu = listing.get(f"codeUnitContaining{self.address}")
        if cu is None:
            return None
        cu_addr = cu.get_min_address()
        if isinstance(cu, Data) and not self.address == cu_addr:
            data = cu
            return data.primitive_at(self.address - cu_addr)
        return cu

    @property
    def status_msg(self) -> str:
        return self.message


class Program(dict):
    pass


class CodeUnit(dict):
    def get_min_address(self) -> int:
        pass

    def set_comment(self, comment_type: int, new_comment: str):
        pass

    def __getattr__(self, item):
        if item == "comment":
            return self.comment
        raise AttributeError(item)


class Data(CodeUnit):
    def primitive_at(self, offset: int) -> CodeUnit:
        pass


if __name__ == "__main__":
    address = 0x12345678
    comment_type = 1
    comment = "This is a test"
    separator = "-"
    cmd = AppendCommentCmd(address, comment_type, comment, separator)
```

Please note that this translation does not include the actual implementation of `Program`, `CodeUnit` and `Data` classes as they are abstract in Java.