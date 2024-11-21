class DbgModuleMemoryImpl:
    def __init__(self, index: str, vma_start: int, vma_end: int, allocation_base: int,
                 allocation_protect: list[str], protect: list[str], state: PageState, type: str,
                 is_read: bool, is_write: bool, is_exec: bool):
        self.index = index
        self.vma_start = vma_start
        self.vma_end = vma_end
        self.allocation_base = allocation_base
        self.state = state
        self.type = type
        self.is_read = is_read
        self.is_write = is_write
        self.is_exec = is_exec

    def get_name(self) -> str:
        return self.index

    def get_id(self) -> int:
        return self.vma_start

    def get_vma_start(self) -> int:
        return self.vma_start

    def get_vma_end(self) -> int:
        return self.vma_end

    def get_allocation_base(self) -> int:
        return self.allocation_base

    def get_allocation_protect(self) -> list[str]:
        return self.allocation_protect

    def get_protect(self) -> list[str]:
        return self.protect

    def get_state(self) -> str:
        return str(self.state)

    def get_type(self) -> str:
        return self.type

    def is_read(self) -> bool:
        return self.is_read

    def is_write(self) -> bool:
        return self.is_write

    def is_exec(self) -> bool:
        return self.is_exec
