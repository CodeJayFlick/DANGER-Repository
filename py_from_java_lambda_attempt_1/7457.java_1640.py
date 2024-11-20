Here is the translation of the given Java code into Python:

```Python
class MachoConstructorDestructorAnalyzer:
    NAME = "Mach-O Constructor/ Destructor"
    DESCRIPTION = "Creates pointers to global constructors and destructors in a Mach-O file."
    CONSTRUCTOR = "__constructor"
    DESTRUCTOR = "__destructor"

    def __init__(self):
        self.priority = AnalysisPriority.FORMAT_ANALYSIS

    def added(self, program: Program, set: AddressSetView, monitor: TaskMonitor, log: MessageLog) -> bool:
        blocks = get_blocks(program)
        
        for block in blocks:
            current_address = block.start
            
            while not monitor.is_cancelled():
                if current_address >= block.end:
                    break
                try:
                    data = program.get_listing().create_data(current_address, PointerDataType())
                    current_address += data.length
                except (CodeUnitInsertionException, DataTypeConflictException):
                    break

        return False


    def can_analyze(self, program: Program) -> bool:
        return not get_blocks(program).empty()


    def default_enablement(self, program: Program) -> bool:
        return self.can_analyze(program)


    @staticmethod
    def check_if_valid(program: Program) -> bool:
        return not get_blocks(program).empty()


    @staticmethod
    def get_blocks(program: Program) -> List[MemoryBlock]:
        blocks = []
        
        if program.executable_format == MachoLoader.MACH_O_NAME:
            for block in program.memory.blocks:
                if block.name == MachoConstructorDestructorAnalyzer.CONSTRUCTOR or block.name == MachoConstructorDestructorAnalyzer.DESTRUCTOR:
                    blocks.append(block)

        return blocks


class Program:
    def __init__(self):
        pass

    @property
    def executable_format(self) -> str:
        pass

    @property
    def memory(self) -> MemoryBlock:
        pass

    @property
    def get_listing(self) -> Listing:
        pass


class AddressSetView:
    def is_cancelled(self) -> bool:
        pass


class TaskMonitor:
    def is_cancelled(self) -> bool:
        pass


class MessageLog:
    pass


class AnalysisPriority:
    FORMAT_ANALYSIS = "FORMAT ANALYSIS"


class PointerDataType:
    pass


class CodeUnitInsertionException(Exception):
    pass


class DataTypeConflictException(Exception):
    pass
```

Note: This translation is not a direct conversion, but rather an equivalent Python code that achieves the same functionality as the given Java code.