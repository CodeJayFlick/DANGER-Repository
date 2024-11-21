class XRefFieldLocation:
    def __init__(self, program: 'Program', addr: int, component_path=None, ref_addr: int = None,
                 index: int = 0, char_offset: int = 0):
        super().__init__(program, addr, component_path, ref_addr, 0, index, char_offset)

    def __init_xml_restoring(self):
        self.__init__()

    @property
    def index(self) -> int:
        return self.get_column()

    def __str__(self) -> str:
        return super().__str__() + f", reAddr={self.ref_addr}"

class Program:  # This is not a real Python class, just for demonstration purposes
    pass

from typing import Optional

Program = type('Program', (), {})  # Create an empty class for demonstration purposes only
