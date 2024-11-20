class TypeDefine:
    def __init__(self):
        self.data_type = None
        self.call_back = False
        self.value = ''
        self.parameters = []

    @property
    def data_type(self):
        return self._data_type

    @data_type.setter
    def data_type(self, value):
        self._data_type = value

    @property
    def call_back(self):
        return self._call_back

    @call_back.setter
    def call_back(self, value):
        self._call_back = value

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, value):
        self._value = value

    @property
    def parameters(self):
        return self._parameters

    @parameters.setter
    def parameters(self, value):
        self._parameters = value


def parse(init_ctx, specs_ctx):
    type_define = TypeDefine()
    data_type = None  # equivalent to DataType in Java
    type_define.data_type = data_type

    ctx = init_ctx.initDeclarator().declarator().directDeclarator()
    callback_ctx = ctx.directDeclarator() if hasattr(ctx, 'directDeclarator') else None
    if callback_ctx is None:
        data_type.type = ctx.getText()
    else:
        type_define.call_back = True
        data_type.type = callback_ctx.declarator().directDeclarator().getText()
        param_list_ctx = ctx.parameterTypeList()  # equivalent to ParameterTypeListContext in Java
        parameters = type_define.parameters
        Parameter.parse_params(parameters, param_list_ctx)

    list_ = []
    for i in range(1, specs_ctx.getChildCount()):
        list_.append(specs_ctx.getChild(i).getText())

    type_define.value = ' '.join(list_)
    return type_define


class DataType:
    def __init__(self):
        self.type = ''

    @property
    def type(self):
        return self._type

    @type.setter
    def type(self, value):
        self._type = value


class Parameter:
    @staticmethod
    def parse_params(parameters, param_list_ctx):
        # equivalent to the logic in Java's Parameter.parseParams()
        pass
