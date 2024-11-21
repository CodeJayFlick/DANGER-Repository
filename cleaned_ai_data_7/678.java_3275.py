class DbgStackFrame:
    def __init__(self):
        pass

    def get_address(self) -> int:
        # Replace with actual implementation
        return 0

    def get_function_name(self) -> str:
        # Replace with actual implementation
        return ""

    def get_level(self) -> int:
        # Replace with actual implementation
        return 0

    async def set_active(self):
        # Replace with actual implementation
        await CompletableFuture(None)

    def get_thread(self) -> 'DbgThread':
        # Replace with actual implementation
        return None

class DbgThread:
    pass

# You would need to implement the following methods in your classes:

def get_func_table_entry(self) -> int:
    raise NotImplementedError()

def get_frame_offset(self) -> int:
    raise NotImplementedError()

def get_return_offset(self) -> int:
    raise NotImplementedError()

def get_stack_offset(self) -> int:
    raise NotImplementedError()

def is_virtual(self) -> bool:
    raise NotImplementedError()

def get_params(self) -> list[int]:
    raise NotImplementedError()
