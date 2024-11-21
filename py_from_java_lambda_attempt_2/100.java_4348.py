Here is the translation of the Java code to Python:
```
class WritesTargetProgramByteBlockSet(ProgramByteBlockSet):
    def __init__(self, provider: 'DebuggerMemoryBytesProvider', program: Program, bbcm: ByteBlockChangeManager):
        super().__init__(provider, program, bbcm)
        self.provider = provider

    def new_memory_byte_block(self, memory: Memory, memblock: MemoryBlock) -> MemoryByteBlock:
        return WritesTargetMemoryByteBlock(self, self.program, memory, memblock)

class DebuggerMemoryBytesProvider:
    pass  # implementation not provided in the original code

class ProgramByteBlockSet:
    pass  # implementation not provided in the original code

class ByteBlockChangeManager:
    pass  # implementation not provided in the original code

class MemoryByteBlock:
    pass  # implementation not provided in the original code

class WritesTargetMemoryByteBlock(MemoryByteBlock):
    def __init__(self, parent: WritesTargetProgramByteBlockSet, program: Program, memory: Memory, memblock: MemoryBlock):
        super().__init__()
        self.parent = parent
        self.program = program
        self.memory = memory
        self.memblock = memblock

class DebuggerMemoryBytesProvider:
    pass  # implementation not provided in the original code

class Program(ProgramByteBlockSet):  # assuming this is a subclass of ProgramByteBlockSet, but actual implementation unknown
pass

class Memory(MemoryByteBlock):
    pass  # implementation not provided in the original code

class MemoryBlock(MemoryByteBlock):
    pass  # implementation not provided in the original code
```
Note that I've kept the same class names and structure as the original Java code, but replaced the imports with Python's equivalent syntax. Additionally, some classes (e.g., `DebuggerMemoryBytesProvider`, `ProgramByteBlockSet`) have been left without an implementation since their actual behavior is unknown based on this snippet alone.

Also note that I've used type hints for function parameters and return types to help maintain consistency in the codebase.