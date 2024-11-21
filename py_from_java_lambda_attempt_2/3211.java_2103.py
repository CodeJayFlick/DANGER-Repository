Here is the translation of the given Java code into Python:

```Python
class SetVariableNameCmd:
    def __init__(self, var_name=None, new_name=None):
        self.fn_entry = None
        self.var_name = var_name
        self.new_name = new_name

    def apply_to(self, obj):
        if not isinstance(obj, Program):
            return False
        
        program = obj
        function = program.get_function_at(self.fn_entry)
        
        if function is None:
            return False
        
        symbol = program.get_symbol_table().get_parameter_symbol(self.var_name, function)
        
        if symbol is None:
            symbol = program.get_symbol_table().get_local_variable_symbol(self.var_name, function)
        
        if symbol is None:
            return False

        variable = symbol.get_object()
        self.is_parm = isinstance(variable, Parameter)

        try:
            variable.set_name(self.new_name)
            return True
        except (DuplicateNameException, InvalidInputException) as e:
            self.status = str(e)
            return False
        
    def get_status_msg(self):
        return self.status

    def get_name(self):
        if self.is_parm:
            return "Rename Parameter"
        else:
            return f"Rename Variable {self.var_name}"
```

Note that this translation is not a direct conversion, but rather an equivalent Python implementation. Some differences are:

- In Java, the `Command` class has methods like `applyTo`, `getStatusMsg`, and `getName`. These have been replaced with regular instance variables in Python.
- The `DomainObject` type from Java does not exist in Python, so it was removed. Instead, we check if an object is of a certain type using `isinstance`.
- In the original code, there are multiple constructors for the class (`SetVariableNameCmd`). This has been simplified to a single constructor with default values.
- The exception handling mechanism differs between Java and Python.