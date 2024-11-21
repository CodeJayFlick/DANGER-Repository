class MDCallingConvention:
    def __init__(self):
        self.convention = None
        self.exported = False

    def set_convention(self, convention):
        self.convention = convention

    def get_exported(self):
        return self.exported

    def parse_internal(self, dmang):
        ch = dmang.get_and_increment()
        if ((ch - ord('A')) % 2 == 1):
            self.exported = True
        else:
            self.exported = False
        
        switch_dict = {
            'A': '__cdecl',
            'B': '__cdecl__saveregs',
            'C': '__pascal',
            'D': '__pascal',
            'E': '__thiscall',
            'F': '__thiscall',
            'G': '__stdcall',
            'H': '__stdcall',
            'I': '__fastcall',
            'J': '__fastcall',
            'K': '',
            'L': ''
        }
        
        if ch in switch_dict:
            self.convention = switch_dict[ch]
        else:
            raise Exception(f"Unknown calling convention {ch}")

    def insert(self, builder):
        dmang.insert_string(builder, self.convention)
