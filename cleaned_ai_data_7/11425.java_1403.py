class AssemblyExtendedNonTerminal:
    def __init__(self, start, nt, end):
        self.name = f"{start}[{nt.name}]{end}"
        self.nt = nt
        self.end = end

    def get_name(self):
        if self.end == -1:
            return self.nt.get_name()
        else:
            return self.name

    def __str__(self):
        if self.end == -1:
            return str(self.nt)
        else:
            return self.name
