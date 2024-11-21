class S_COMPILE:
    @classmethod
    def create_s_compile(cls, length: int, type: int) -> 'S_COMPILE':
        return cls(length, type)

    def __init__(self, length: int, type: int):
        self.process_debug_symbol(length, type)

def process_debug_symbol(self, length: int, type: int):
    # your code here
