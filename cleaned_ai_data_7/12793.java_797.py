class MemoryBlockStartFieldLocation:
    def __init__(self, program: 'Program', addr: int, component_path: list[int], row: int,
                 char_offset: int, comment: str | None = None) -> None:
        super().__init__(program=program, addr=addr, component_path=component_path, comment=comment,
                         code_unit_comment=None, row=row, char_offset=char_offset)

    def __init_subclass__(cls):
        pass
