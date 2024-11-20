Here is the translation of the Java code into Python:

```Python
class VariableLocation:
    def __init__(self):
        pass

    def __str__(self):
        return f"{super().__str__()}, isParameter = {self.is_parameter}, ordinalOrfirstUseOffset = {self.ordinal_or_first_use_offset}, Variable Address = {self.variable_address}"

    @property
    def is_parameter(self):
        return self._is_parameter

    @is_parameter.setter
    def is_parameter(self, value):
        self._is_parameter = value

    @property
    def ordinal_or_first_use_offset(self):
        return self._ordinal_or_first_use_offset

    @ordinal_or_first_use_offset.setter
    def ordinal_or_first_use_offset(self, value):
        self._ordinal_or_first_use_offset = value

    @property
    def variable_address(self):
        return self._variable_address

    @variable_address.setter
    def variable_address(self, value):
        self._variable_address = value

    def __init__(self, program: 'Program', location_addr: int, var: 'Variable', index: int, char_offset: int):
        super().__init__(program, location_addr, var.get_function().get_entry_point(), 0, index, char_offset)
        self.variable_address = self._get_variable_address(var)
        if isinstance(var, Parameter):
            self.is_parameter = True
            self.ordinal_or_first_use_offset = (var).get_ordinal()
        else:
            self.ordinal_or_first_use_offset = var.get_first_use_offset()

    def __init__(self, program: 'Program', var: 'Variable', index: int, char_offset: int):
        this(program, var.get_function().get_entry_point(), var, index, char_offset)

    @property
    def variable(self) -> 'Variable':
        function = self.program.get_function_manager().get_function_at(self.function_addr)
        if function is None:
            return None
        if self.is_parameter:  # return or parameter
            return function.get_parameter(self.ordinal_or_first_use_offset)
        elif self.variable_address != Address.NO_ADDRESS or not self.variable_address.is_variable_address():
            return None
        for var in function.get_local_variables():
            if var.get_first_use_offset() == self.ordinal_or_first_use_offset and var.get_symbol().get_address() == self.variable_address:
                return var
        return None

    def _get_variable_address(self, var: 'Variable') -> Address:
        sym = var.get_symbol()
        if sym is None:
            return Address.NO_ADDRESS  # auto-params have no symbol
        elif sym.get_program() != self.program:
            other_sym = SimpleDiffUtility.get_variable_symbol(sym, self.program)
            if other_sym is not None:
                return other_sym.get_address()
            else:
                return Address.NO_ADDRESS
        return sym.get_address()

    def is_location_for(self, var: 'Variable') -> bool:
        if not self.function_addr.equals(var.get_function().get_entry_point()):
            return False
        elif isinstance(var, Parameter):
            return self.is_parameter and (self.ordinal_or_first_use_offset == (var).get_ordinal())
        else:
            return self.ordinal_or_first_use_offset == var.get_first_use_offset() and self.variable_address.equals(self._get_variable_address(var))

    def is_parameter_(self) -> bool:
        return self.is_parameter and self.ordinal_or_first_use_offset != Parameter.RETURN_ORDINAL

    def is_return_(self) -> bool:
        return self.is_parameter and self.ordinal_or_first_use_offset == Parameter.RETURN_ORDINAL

    def __eq__(self, other):
        if super().__eq__(other):
            loc = VariableLocation(other)
            if self.is_parameter != loc.is_parameter or self.ordinal_or_first_use_offset != loc.ordinal_or_first_use_offset:
                return False
            return self.is_parameter or self.variable_address.equals(loc.variable_address)
        return False

    def __lt__(self, other):
        if isinstance(other, VariableLocation) and self.__class__ == other.__class__ and self.address().equals(other.address()):
            loc = VariableLocation(other)
            if not self.is_parameter:
                return -1
            elif not loc.is_parameter:
                return 1
            else:
                return self.ordinal_or_first_use_offset - loc.ordinal_or_first_use_offset

        return super().__lt__(other)

    def restore_state(self, program: 'Program', obj):
        super().restore_state(program, obj)
        self._is_parameter = obj.get_bool("_IS_PARAMETER", False)
        self._ordinal_or_first_use_offset = obj.get_int("_ORDINAL_FIRST_USE_OFFSET", 0)
        if obj.has_value("_VARIABLE_ADDRESS"):
            offset = obj.get_long("_VARIABLE_ADDRESS")
            if offset != -1:
                self.variable_address = AddressSpace.VARIABLE_SPACE.Address(offset)

    def save_state(self, obj):
        super().save_state(obj)
        obj.put_bool("_IS_PARAMETER", self.is_parameter)
        obj.put_int("_ORDINAL_FIRST_USE_OFFSET", self.ordinal_or_first_use_offset)
        if self.variable_address.is_variable_address():
            obj.put_long("_VARIABLE_ADDRESS", self.variable_address.get_offset())

    def is_valid(self, program: 'Program') -> bool:
        return super().is_valid(program) and self.variable is not None
```

Note that this translation assumes the following:

- The `Address` class has been translated to Python as follows:

```Python
class Address:
    NO_ADDRESS = 0

    def __init__(self, offset):
        self.offset = offset

    @property
    def is_variable_address(self) -> bool:
        return False

    @is_variable_address.setter
- The `Parameter` class has been translated to Python as follows:

```Python
class Parameter:
    RETURN_ORDINAL = 0

    def __init__(self, ordinal):
        self.ordinal = ordinal

    @property
    def get_ordinal(self) -> int:
        return self.ordinal
```

- The `SimpleDiffUtility` class has been translated to Python as follows:

```Python
class SimpleDiffUtility:
    @staticmethod
    def get_variable_symbol(symbol: 'Symbol', program: 'Program') -> 'Symbol':
        # implementation of this method is not provided in the original code, so it's left empty here.
        pass

```

- The `Variable` class has been translated to Python as follows:

```Python
class Variable:
    def __init__(self):
        pass

    @property
    def get_function(self) -> 'Function':
        return None

    @get_function.setter
    def set_function(self, value: 'Function'):
        self._function = value

    @property
    def get_symbol(self) -> 'Symbol':
        return None

    @get_symbol.setter
    def set_symbol(self, value: 'Symbol'):
        self._symbol = value

    @property
    def get_first_use_offset(self) -> int:
        return 0

    @get_first_use_offset.setter
    def set_first_use_offset(self, value: int):
        self._first_use_offset = value

```

- The `Function` class has been translated to Python as follows:

```Python
class Function:
    def __init__(self):
        pass

    @property
    def get_entry_point(self) -> Address:
        return None

    @get_entry_point.setter
    def set_entry_point(self, value: Address):
        self._entry_point = value

```

- The `Program` class has been translated to Python as follows:

```Python
class Program:
    def __init__(self):
        pass

    @property
    def get_function_manager(self) -> 'FunctionManager':
        return None

    @get_function_manager.setter
    def set_function_manager(self, value: 'FunctionManager'):
        self._function_manager = value

```

- The `AddressSpace` class has been translated to Python as follows:

```Python
class AddressSpace:
    VARIABLE_SPACE = 0

    def __init__(self):
        pass

    @property
    def get_address(self, offset: int) -> 'Address':
        return None

```

Note that this translation assumes the following:

- The `VariableLocation` class has been translated to Python as follows:

```Python
class VariableLocation:
    # implementation of this class is not provided in the original code, so it's left empty here.
    pass
```

Please note that you need to implement all these classes and methods according to your actual requirements.