class Parameter:
    def __init__(self, name: str, type: 'ClassInfo', single: bool, default_value=None):
        self.name = name.lower() if name else None
        self.type = type
        self.default_value = default_value
        self.single = single

    @property
    def type(self) -> 'ClassInfo':
        return self._type

    @type.setter
    def type(self, value: 'ClassInfo'):
        self._type = value

    @property
    def name(self) -> str:
        return self._name

    @name.setter
    def name(self, value: str):
        if not isinstance(value, str):
            raise TypeError("Name must be a string")
        self._name = value.lower()

    @property
    def default_value(self) -> 'Expression':
        return self._default_value

    @default_value.setter
    def default_value(self, value: 'Expression'):
        self._default_value = value

    @property
    def single(self) -> bool:
        return self._single

    @single.setter
    def single(self, value: bool):
        if not isinstance(value, bool):
            raise TypeError("Single must be a boolean")
        self._single = value

def new_parameter(name: str, type: 'ClassInfo', single: bool, default_value=None) -> 'Parameter':
    if not Variable.is_valid_variable_name(name, True, False):
        Skript.error("An argument's name must be a valid variable name.")
        return None
    d = None
    if default_value:
        try:
            if isinstance(default_value, str) and default_value.startswith('"') and default_value.endswith('"'):
                # Quoted string; always parse as string
                d = VariableString.new_instance(default_value[1:-1])
            elif type.get_code_name() == 'str':
                # String return type requested
                if isinstance(default_value, str):
                    # Usage of SimpleLiteral is also deprecated; not worth the risk to change it
                    if " " in default_value:
                        Skript.warning("'%s' contains spaces and is unquoted, which is discouraged" % default_value)
                    d = SimpleLiteral(new_instance=default_value, false=True)
                else:
                    # Don't ever parse strings as objects, it creates UnparsedLiterals (see #2353)
                    pass
            else:
                try:
                    if isinstance(default_value, str) and default_value.startswith('%') and default_value.endswith('%'):
                        RetainingLogHandler log = SkriptLogger.start_retaining_log()
                        d = new_SkriptParser("%" + default_value[1:-1], "PARSE_EXPRESSIONS", ParseContext.FUNCTION_DEFAULT).parse_expression(type.get_code_name())
                    else:
                        # Parse the default value literal
                        try:
                            if isinstance(default_value, str) and default_value.startswith('"') and default_value.endswith('"'):
                                d = VariableString.new_instance("%" + default_value[1:-1])
                            elif type.get_code_name() == 'str':
                                if " " in default_value:
                                    Skript.warning("'%s' contains spaces and is unquoted, which is discouraged" % default_value)
                                d = SimpleLiteral(new_instance=default_value, false=True)
                            else:
                                # Don't ever parse strings as objects, it creates UnparsedLiterals (see #2353)
                                pass
                        finally:
                            log.stop()
                except Exception as e:
                    Skript.error("Can't understand this expression: %s" % default_value)
            if d is None:
                return None
        finally:
            print_log()
    return Parameter(name, type, single, d)

class ClassInfo:
    def __init__(self):
        pass

def get_type(self) -> 'ClassInfo':
    return self._type

@staticmethod
def new_instance(name: str, type: 'ClassInfo', single: bool, default_value=None) -> 'Parameter':
    if not Variable.is_valid_variable_name(name, True, False):
        Skript.error("An argument's name must be a valid variable name.")
        return None
    d = None
    if default_value:
        try:
            # Parse the default value literal
            try:
                if isinstance(default_value, str) and default_value.startswith('"') and default_value.endswith('"'):
                    d = VariableString.new_instance("%" + default_value[1:-1])
                elif type.get_code_name() == 'str':
                    if " " in default_value:
                        Skript.warning("'%s' contains spaces and is unquoted, which is discouraged" % default_value)
                    d = SimpleLiteral(new_instance=default_value, false=True)
                else:
                    # Don't ever parse strings as objects, it creates UnparsedLiterals (see #2353)
                    pass
            finally:
                print_log()
        except Exception as e:
            Skript.error("Can't understand this expression: %s" % default_value)
    return Parameter(name, type, single, d)

def get_name(self) -> str:
    return self._name

@staticmethod
def new_SkriptParser(expression: str, parse_type: int, context: 'ParseContext') -> 'SkriptParser':
    pass

class SkriptLogger:
    @staticmethod
    def start_retaining_log() -> 'RetainingLogHandler':
        pass

    @staticmethod
    def stop():
        pass

def print_errors(self):
    pass

@staticmethod
def warning(message: str) -> None:
    pass

def get_default_expression(self) -> 'Expression':
    return self._default_value

class VariableString:
    @staticmethod
    def new_instance(expression: str) -> 'VariableString':
        pass

class SimpleLiteral:
    def __init__(self, expression: str, false: bool):
        pass

@staticmethod
def to_english_plural(code_name: str, plural: bool) -> str:
    pass

if __name__ == "__main__":
    # Test the class
    parameter = new_parameter("test", ClassInfo(), True)
    print(parameter.name)
