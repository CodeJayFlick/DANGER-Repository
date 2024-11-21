class DbgStackFrameImpl:
    def __init__(self, thread: 'DbgThread', level: int, addr: 'BigInteger', func=None):
        self.manager = thread.manager
        self.thread = thread
        self.level = level
        self.addr = addr
        self.func = func

    @property
    def get_level(self) -> int:
        return self.level

    @property
    def get_address(self) -> 'BigInteger':
        return self.addr

    @property
    def get_function(self) -> str:
        return self.func

    @property
    def get_thread(self) -> 'DbgThread':
        return self.thread

    @property
    def get_func_table_entry(self) -> int:
        return 0  # Replace with actual implementation

    @property
    def get_frame_offset(self) -> int:
        return 0  # Replace with actual implementation

    @property
    def get_return_offset(self) -> int:
        return 0  # Replace with actual implementation

    @property
    def get_stack_offset(self) -> int:
        return 0  # Replace with actual implementation

    @property
    def is_virtual(self) -> bool:
        return False  # Replace with actual implementation

    @property
    def params(self) -> list[int]:
        return [0, 0, 0, 0]  # Replace with actual implementation

    def __str__(self):
        if self.func:
            return f"<DbgStackFrame: level={self.level}, addr=0x{self.addr.hex()}, func='{self.func}'>"
        else:
            return f"<DbgStackFrame: level={self.level}, addr=0x{self.addr.hex()}>"

    def set_active(self) -> 'CompletableFuture[Void]':
        # Replace with actual implementation
        pass

    async def evaluate(self, expression: str):
        # Replace with actual implementation
        return None  # Return a result or raise an exception if necessary

    async def read_registers(self, regs: list['DbgRegister']) -> 'CompletableFuture[Map[DbgRegister, BigInteger]]':
        # Replace with actual implementation
        pass

    async def write_registers(self, reg_vals: dict['DbgRegister', int]) -> 'CompletableFuture[Void]':
        # Replace with actual implementation
        pass

    async def console(self, command: str) -> 'CompletableFuture[Void]':
        # Replace with actual implementation
        pass

    async def console_capture(self, command: str) -> 'CompletableFuture[str]':
        # Replace with actual implementation
        pass


class DbgThread:
    def __init__(self):
        self.manager = None  # Replace with actual implementation

    @property
    def get_manager(self) -> object:
        return self.manager

    async def set_active(self) -> 'CompletableFuture[Void]':
        # Replace with actual implementation
        pass


class DbgRegister:
    pass
