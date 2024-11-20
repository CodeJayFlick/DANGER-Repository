Here is the translation of the Java code into Python:

```Python
class AbstractFunctionTypeApplier:
    def __init__(self, applicator, ms_type):
        self.applicator = applicator
        self.ms_type = ms_type
        self.function_definition = FunctionDefinitionDataType(applicator.get_anonymous_functions_category(), "_func", applicator.get_data_type_manager())
        self.data_type = self.function_definition

    def deferred_apply(self):
        if is_deferred():
            apply_internal()

    @property
    def function_definition(self):
        return self._function_definition

    @function_definition.setter
    def function_definition(self, value):
        self._function_definition = value

    def get_cycle_break_type(self):
        if self.data_type:
            return self.data_type
        return self.function_definition

    def get_return_type_applier(self):
        return self.applicator.get_type_applier(get_return_record_number())

    @property
    def args_list_applier(self):
        return self._args_list_applier

    @args_list_applier.setter
    def args_list_applier(self, value):
        self._args_list_applier = value

    def get_calling_convention(self):
        pass  # abstract method

    def has_this_pointer(self):
        pass  # abstract method

    def get_return_record_number(self):
        pass  # abstract method

    def get_arg_list_record_number(self):
        pass  # abstract method

    @property
    def is_constructor(self):
        return False

    def apply_function(self, calling_convention_param, has_this_pointer_param):
        self.calling_convention = calling_convention_param
        self.has_this_pointer = has_this_pointer_param
        self.return_applier = get_return_type_applier()
        self.args_list_applier = get_args_list_applier()

        try:
            apply_or_defer_for_dependencies()
        except CancelledException as e:
            pass  # handle exception

    def apply_or_defer_for_dependencies(self):
        if is_deferred():
            applicator.add_applier_dependency(self, return_applier)
            set_deferred()
        elif args_list_applier and not is_deferred():
            args_list_applier.check_for_dependencies(self)

        try:
            apply_internal()
        except CancelledException as e:
            pass  # handle exception

    def apply_internal(self):
        if applied():
            return
        if not set_return_type():
            return
        if self.args_list_applier and not is_deferred():
            args_list_applier.apply_to(self)
        try:
            set_calling_convention(applicator, calling_convention, has_this_pointer)
        except CancelledException as e:
            pass  # handle exception

    def set_return_type(self):
        if self.is_constructor:
            return True
        data_type = get_return_applier().get_data_type()
        if not data_type:
            applicator.append_log_msg("Return type is null in " + function_definition.name)
            return False
        self.function_definition.set_return_type(data_type)
        return True

    def set_calling_convention(self, applicator, calling_convention, has_this_pointer):
        convention = GenericCallingConvention.thiscall if has_this_pointer else None
```

Please note that this is a direct translation of the Java code into Python. The abstract methods `get_calling_convention`, `has_this_pointer`, `get_return_record_number` and `get_arg_list_record_number` are left as they were in the original Java code, since their implementation depends on specific details not provided here.