Here's a translation of your Java code into equivalent Python:

```Python
class ConvertConstantAction:
    def __init__(self, plugin: 'DecompilePlugin', name: str, convert_type: int):
        self.plugin = plugin
        self.convert_type = convert_type

    @property
    def metrics(self) -> 'FontMetrics':
        if not hasattr(self, '_metrics'):
            item = JMenuItem()
            font = item.getFont()
            window = self.plugin.get_tool().get_active_window()
            self._metrics = window.get_font_metrics(font)
        return self._metrics

    def get_standard_length_string(self, base_string: str) -> str:
        if not hasattr(self, '_base_width'):
            self._base_width = self.metrics.string_width(base_string)

        space_width = self.metrics.string_width('  ')
        padding_size = (140 - self._base_width) // space_width
        if padding_size <= 0:
            return base_string

        buf = StringBuilder(base_string)
        for _ in range(padding_size):
            buf.append(' ')

        return str(buf)

    def find_scalar_in_instruction(self, instruction: 'Instruction', values: list) -> tuple or None:
        num_operands = instruction.get_num_operands()
        scalar_match = None
        for i in range(num_operands):
            for obj in instruction.get_op_objects(i):
                if isinstance(obj, Scalar):
                    scalar = obj
                    for value in values:
                        if scalar.get_unsigned_value() != value:
                            continue

                        if scalar_match is not None:
                            return (scalar_match[0], -1)  # non-unique scalar operand value - can't identify operand

                        scalar_match = (instruction.get_address(), scalar, i)
        return scalar_match

    def find_scalar_match(self, program: 'Program', start_address: Address, const_vn: Varnode,
                           monitor: TaskMonitor or None) -> tuple or None:
        value = const_vn.get_offset()
        mask = -1
        if const_vn.get_size() < 8:
            mask >>= (8 - const_vn.get_size()) * 8

        values = [value, value - 1 & mask, value + 1 & mask, -value & mask]
        count = 0
        scalar_match = None
        cur_inst = program.get_listing().get_instruction_at(start_address)
        if not hasattr(self, '_basic_block'):
            self._basic_block = SimpleBlockModel(program).get_first_code_block_containing(start_address, monitor)

        while count < MAX_INSTRUCTION_WINDOW:
            count += 1
            scalar_match_new = find_scalar_in_instruction(cur_inst, values)
            if scalar_match_new is not None:
                if scalar_match is not None:
                    return (None,)  # Matches at more than one address

                if scalar_match_new[2] < 0:  # Matches at more than one operand
                    return (None,)
                scalar_match = scalar_match_new
            cur_inst = cur_inst.get_previous()
            if cur_inst is None or not self._basic_block.contains(cur_inst.get_address()):
                break

        return scalar_match

    def establish_task(self, context: 'DecompilerActionContext', setup_final: bool) -> tuple:
        token_at_cursor = context.get_token_at_cursor()
        if not isinstance(token_at_cursor, ClangVariableToken):
            return None
        convert_vn = token_at_cursor.get_varnode()
        if convert_vn is None or not convert_vn.is_constant():
            return None

        high_symbol = convert_vn.get_high().get_symbol()
        if high_symbol is not None:
            if isinstance(high_symbol, EquateSymbol):
                equate_symbol = high_symbol
                type_ = equate_symbol.get_convert()
                if type_ == self.convert_type or type_ == EquateSymbol.FORMAT_DEFAULT:
                    return None

            else:  # Something already attached to constant
                return None

        convert_data_type = convert_vn.get_high().get_data_type()
        is_signed = False
        if isinstance(convert_data_type, AbstractIntegerDataType):
            if isinstance(convert_data_type, BooleanDataType):
                return None
            is_signed = convert_data_type.is_signed()

        elif isinstance(convert_data_type, Enum):
            return None

        task = None
        equate_name = get_equate_name(convert_vn.get_offset(), convert_vn.get_size(),
                                       is_signed, context.get_program())
        if setup_final:
            program = context.get_program()
            address = high_symbol.get_pc_address() if isinstance(high_symbol, EquateSymbol) else None
            hash_value = 0

            equates = program.get_equate_table().get_equates(address)
            for equate in equates:
                if equate.get_value() != convert_vn.get_offset():
                    continue

                for reference in equate.get_references(address):
                    hash_value = reference.get_dynamic_hash_value()
                    op_index = reference.get_op_index()

                    task = ConvertConstantTask(context, equate_name, address,
                                               convert_vn, hash_value, op_index)
                    break
            if not hasattr(self, '_scalar_match'):
                try:
                    scalar_match = find_scalar_match(program, start_address, const_vn, TaskMonitor.DUMMY)
                    if scalar_match is not None:
                        value = scalar_match[1].get_unsigned_value()
                        size = scalar_match[2]
                        alt_name = get_equate_name(value, size, is_signed, program)

                        task.set_alternate(alt_name, scalar_match[0], scalar_match[2], value)
                except CancelledException as e:
                    pass

        return task

    def decompiler_action_performed(self, context: 'DecompilerActionContext'):
        if self.establish_task(context, True) is None:
            return
        self.establish_task(context, False).run()

    @property
    def menu_prefix(self):
        raise NotImplementedError('Method must be implemented by subclass')

    @abstractmethod
    def get_menu_display(self, value: int, size: int, is_signed: bool) -> str:
        pass

    @abstractmethod
    def get_equate_name(self, value: int, size: int, is_signed: bool, program: 'Program') -> str:
        pass


class ConvertConstantTask:
    def __init__(self, context: 'DecompilerActionContext', equate_name: str,
                 address: Address or None, varnode: Varnode, hash_value: int, op_index: int):
        self.context = context
        self.equate_name = equate_name
        self.address = address
        self.varnode = varnode
        self.hash_value = hash_value
        self.op_index = op_index

    def set_alternate(self, alt_name: str, scalar_match_address: Address,
                      scalar_match_op_index: int, value: int):
        pass

    def run_task(self) -> None:
        pass


class JMenuItem:
    @property
    def font(self) -> 'Font':
        raise NotImplementedError('Method must be implemented by subclass')

    @property
    def get_font_metrics(self) -> 'FontMetrics':
        raise NotImplementedError('Method must be implemented by subclass')


class FontMetrics:
    @abstractmethod
    def string_width(self, s: str) -> int:
        pass


class Instruction:
    @property
    def num_operands(self) -> int:
        raise NotImplementedError('Method must be implemented by subclass')

    @property
    def get_op_objects(self, i: int) -> list or None:
        raise NotImplementedError('Method must be implemented by subclass')


class Program:
    @abstractmethod
    def get_listing(self) -> 'Listing':
        pass

    @abstractmethod
    def get_equate_table(self) -> 'EquateTable':
        pass


class Varnode:
    @property
    def offset(self) -> int:
        raise NotImplementedError('Method must be implemented by subclass')

    @property
    def size(self) -> int:
        raise NotImplementedError('Method must be implemented by subclass')


class Address:
    pass


class Listing:
    @abstractmethod
    def get_instruction_at(self, address: 'Address') -> 'Instruction':
        pass


class EquateTable:
    @abstractmethod
    def get_equates(self, start_address: 'Address') -> list or None:
        pass


class DynamicHash:
    def __init__(self, varnode: Varnode, value: int):
        self.varnode = varnode
        self.value = value

    @property
    def hash_value(self) -> int:
        return self.value
```

Please note that this is a direct translation of your Java code into Python. It may not be perfect and might require some adjustments to work correctly in the context you're using it for.

Also, please replace `DecompilePlugin`, `ClangVariableToken`, `AbstractIntegerDataType`, `BooleanDataType`, `Enum` with their actual implementations or imports as needed.