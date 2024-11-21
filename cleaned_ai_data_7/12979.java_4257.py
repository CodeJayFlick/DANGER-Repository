class FunctionTestDouble:
    def __init__(self, name):
        self.name = name

    def __init__(self, name, signature=None):
        if signature is None:
            return
        self.name = name
        self.function_signature = signature

    @property
    def deleted(self):
        return False

    @property
    def to_string(self):
        return self.name

    def get_symbol(self):
        raise NotImplementedError()

    def get_name(self, include_namespace_path=False):
        return self.name

    def get_id(self):
        raise NotImplementedError()

    def get_parent_namespace(self):
        raise NotImplementedError()

    def get_body(self):
        raise NotImplementedError()

    def set_parent_namespace(self, parent_namespace):
        raise NotImplementedError()

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        if not isinstance(value, str):
            raise TypeError("Name must be a string")
        self._name = value

    @property
    def function_signature(self):
        return self._function_signature

    @function_signature.setter
    def function_signature(self, signature):
        if signature is None:
            self._function_signature = None
        elif isinstance(signature, FunctionSignature):
            self._function_signature = signature
        else:
            raise TypeError("Function Signature must be of type FunctionSignature")

    def get_return_type(self):
        return self.function_signature.get_return_type()

    @property
    def prototype_string(self):
        if not self.function_signature:
            raise NotImplementedError()
        return self.function_signature.prototype_string

    @property
    def signature_source(self):
        raise NotImplementedError()

    @signature_source.setter
    def signature_source(self, source):
        raise NotImplementedError()

    def get_stack_frame(self):
        raise NotImplementedError()

    def get_stack_purge_size(self):
        raise NotImplementedError()

    def set_stack_purge_size(self, purge_size):
        raise NotImplementedError()

    def is_stack_purge_size_valid(self):
        raise NotImplementedError()

    @property
    def parameters(self):
        return self._parameters

    @parameters.setter
    def parameters(self, value):
        if not isinstance(value, list) or any(not isinstance(param, Parameter) for param in value):
            raise TypeError("Parameters must be a list of Parameters")
        self._parameters = value

    def add_parameter(self, var, source=None):
        raise NotImplementedError()

    @property
    def auto_parameters(self):
        return self._auto_parameters

    @auto_parameters.setter
    def auto_parameters(self, value):
        if not isinstance(value, int) or value < 0:
            raise TypeError("Auto Parameters must be a non-negative integer")
        self._auto_parameters = value

    @property
    def local_variables(self):
        return self._local_variables

    @local_variables.setter
    def local_variables(self, value):
        if not isinstance(value, list) or any(not isinstance(var, Variable) for var in value):
            raise TypeError("Local Variables must be a list of Variables")
        self._local_variables = value

    def get_all_variables(self):
        return self._all_variables

    @property.setter
    def all_variables(self, value):
        if not isinstance(value, list) or any(not isinstance(var, Variable) for var in value):
            raise TypeError("All Variables must be a list of Variables")
        self._all_variables = value

    # Other methods and properties are similar to the above ones.
