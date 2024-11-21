class FuncInfo:
    def __init__(self):
        self.name = None
        self.return_type = None
        self.parameters = []

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def return_type(self):
        return self._return_type

    @return_type.setter
    def return_type(self, value):
        self._return_type = value

    @property
    def parameters(self):
        return self._parameters

    @parameters.setter
    def parameters(self, value):
        self._parameters = value

    def add_parameter(self, parameter):
        self.parameters.append(parameter)

    def __str__(self):
        sb = StringBuilder()
        if self.return_type:
            sb.append(str(self.return_type))
            sb.append(' ')
            sb.append(self.name)
            sb.append('(')
            first = True
            for param in self.parameters:
                if not first:
                    sb.append(', ')
                else:
                    first = False
                sb.append(str(param))
            sb.append(');')
        return str(sb)

    def __eq__(self, other):
        if self is other:
            return True
        elif isinstance(other, FuncInfo) and (not self.name or not other.name or self.name == other.name) and \
             (not self.parameters or not other.parameters or set(self.parameters) == set(other.parameters)):
            return True
        else:
            return False

    def __hash__(self):
        if self.name is None:
            return 0
        return hash(self.name)

def parse(ctx):
    info = FuncInfo()

    specs = [spec for spec in ctx.declarationSpecifiers().declarationSpecifier()]
    data_types = DataType.parse_data_types(specs)
    info.return_type = data_types[0]
    if len(data_types) > 1:
        info.name = data_types[1].type

    init = ctx.initDeclaratorList().initDeclarator()
    declarator = init.declarator().directDeclarator()

    name = declarator.directDeclarator()
    if not info.name:
        info.name = name.text
        param_list_ctx = declarator.parameterTypeList()
        if param_list_ctx is not None:
            Parameter.parse_params(info.parameters, param_list_ctx)
    else:
        data_type = DataType()
        type_specifier = declarator.typeSpecifier()
        data_type.append_type_name(type_specifier.text)
        if declarator.pointer() is not None:
            data_type.increase_pointer_count()
        param = Parameter(data_type, name.text)
        info.add_parameter(param)

    return info
