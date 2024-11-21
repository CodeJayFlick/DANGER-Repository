class DelimiterState:
    def __init__(self, delim_start: str, delimiter: str):
        self.delim_start = delim_start
        self.delimiter = delimiter
        self.first = True

    def reset(self) -> None:
        self.first = True

    def out(self, output: bool, obj: object) -> str:
        return self.out(output, str(obj))

    def out(self, output: bool, item: 'AbstractParsableItem') -> str:
        return self.out(output, str(item))

    def out(self, output: bool, val: str) -> str:
        if output:
            if self.first:
                self.first = False
                return f"{self.delim_start}{val}"
            else:
                return f"{self.delimiter}{val}"
        return ""
