class SpacerFieldLocation:
    def __init__(self, program: 'Program', addr: int, component_path: list[int], char_offset: int, text: str):
        super().__init__(program=program, addr=addr, component_path=component_path, 0, 0, char_offset)
        self.text = text

    def __str__(self) -> str:
        return f"{super().__str__()}, Spacer text={self.text}"

class Program:
    pass
