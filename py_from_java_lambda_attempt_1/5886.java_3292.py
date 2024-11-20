Here is the translation of the Java code to Python:
```
class Switch:
    def __init__(self):
        pass

    @abstractmethod
    def get_case_address(self, case_index_value) -> int:
        raise NotImplementedError("Must be implemented by subclass")

    @abstractmethod
    def get_index_value(self) -> object:
        raise NotImplementedError("Must be implemented by subclass")


def get_indirect_jump_switch(program: 'Program', v: object) -> 'Switch':
    if not isinstance(v, VarnodeOperation):
        return None

    op = v  # type: VarnodeOperation
    opcode = op.get_pcode_op().get_opcode()
    if opcode == PcodeOp.LOAD:
        table_entry = TableEntry.get_table_entry(program, op)
        if table_entry is not None:
            return table_entry
        return None

    elif opcode == PcodeOp.INT_ADD:
        rel_jump_table_switch = RelativeJumpTableSwitch.get_relative_jump_table_switch(program, op)
        if rel_jump_table_switch is not None:
            return rel_jump_table_switch
        # Relative computed offset (fixed case size - e.g., PIC processors)
        return TableEntryAddress.get_table_entry_address(program.get_address_factory(), op)

    return None


class Program:
    def __init__(self):
        pass

    @property
    def address_factory(self) -> object:
        raise NotImplementedError("Must be implemented by subclass")


class VarnodeOperation:
    def __init__(self, pcode_op: 'PcodeOp'):
        self.pcode_op = pcode_op


class PcodeOp:
    LOAD = 0
    INT_ADD = 1

# Define the rest of the classes and their methods as needed
```
Note that I've used Python's type hinting system to indicate the expected types for method parameters and return values. This is not strictly necessary, but it can help with code readability and catch potential errors at runtime.

Also, some Java-specific concepts like abstract classes and interfaces do not have direct equivalents in Python. Instead, we use Python's built-in support for multiple inheritance and duck typing to achieve similar effects.