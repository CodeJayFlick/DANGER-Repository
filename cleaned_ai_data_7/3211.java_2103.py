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
