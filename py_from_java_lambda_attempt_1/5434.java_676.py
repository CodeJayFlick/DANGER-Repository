Here is the translation of the Java code into Python:

```Python
class FunctionSignatureParser:
    REPLACEMENT_DT_NAME = "__REPLACE_ DT_NAME__"
    REPLACE_NAME = "__REPLACE_NAME__"

    def __init__(self, dest_data_type_manager: 'DataTypeManager', service: 'DataTypeQueryService' = None):
        self.dest_data_type_manager = dest_data_type_manager
        if not (dest_data_type_manager and service) or not all(isinstance(x, str) for x in [dest_data_type_manager, service]):
            raise ValueError("Destination DataTypeManager or DataTypeManagerService provider required")

        if service:
            self.dtm_service = ParserDataTypeManagerService(service)
        else:
            self.dtm_service = None

        self.data_type_parser = DataTypeParser(dest_data_type_manager, dest_data_type_manager, dtm_service)

    def parse(self, original_signature: 'FunctionSignature', signature_text: str) -> 'FunctionDefinitionDataType':
        if not isinstance(original_signature, FunctionSignature):
            raise ValueError("Invalid input type")

        self.dt_map.clear()
        self.name_map.clear()

        if self.dtm_service:
            self.dtm_service.clear_cache()  # clear datatype selection cache

        if original_signature:
            self.init_data_type_map(original_signature)
            signature_text = self.clean_up_signature_text(signature_text, original_signature)

        function_name = self.extract_function_name(signature_text)
        function = FunctionDefinitionDataType(function_name, self.dest_data_type_manager)
        function.set_return_type(self.extract_return_type(signature_text))
        function.set_arguments(self.extract_arguments(signature_text))
        function.set_var_args(self.has_var_args(signature_text))

        return function

    def init_data_type_map(self, signature: 'FunctionSignature'):
        if not isinstance(signature, FunctionSignature):
            raise ValueError("Invalid input type")

        for argument in signature.get_arguments():
            self.cache_data_type(argument.get_data_type())

    @staticmethod
    def cache_data_type(data_type: 'DataType'):
        if data_type is None or (isinstance(data_type, Dynamic) or isinstance(data_type, FactoryDataType)):
            return

        base_type = None
        if isinstance(data_type, Pointer):
            base_type = data_type.get_data_type()
        elif isinstance(data_type, Array):
            base_type = data_type.get_data_type()
        elif isinstance(data_type, TypeDef):
            base_type = data_type.get_data_type()

        self.dt_map[base_type.name] = base_type
        if base_type:
            FunctionSignatureParser.cache_data_type(base_type)

    def has_var_args(self, signature_text: str) -> bool:
        start_index = signature_text.rfind(',')
        end_index = signature_text.find(')')
        if start_index < 0 or end_index < 0 or start_index >= end_index:
            return False

        last_arg = signature_text[start_index + 1:end_index].strip()
        return '...' == last_arg

    def extract_arguments(self, signature_text: str) -> list['ParameterDefinition']:
        if not isinstance(signature_text, str):
            raise ValueError("Invalid input type")

        start_index = signature_text.find('(')
        end_index = signature_text.find(')')
        if start_index < 0 or end_index < 0 or start_index >= end_index:
            return []

        trailing_text = signature_text[end_index + 1:]
        if trailing_text.strip():
            raise ValueError("Unexpected trailing text at the end of function")

        arg_string = signature_text[start_index + 1:end_index].strip()
        if not arg_string:
            return []

        args_list = [arg.strip() for arg in arg_string.split(',')]
        parameter_definitions = []
        for arg in args_list:
            self.add_parameter(parameter_definitions, arg)

        return parameter_definitions

    def add_parameter(self, parameters: list['ParameterDefinition'], arg: str) -> None:
        if '...' == arg:
            return
        elif not arg.strip():
            raise ValueError("Missing parameter")

        try:
            data_type = self.resolve_data_type(arg)
        except CancelledException as e:
            raise

        if data_type is None:
            raise ValueError(f"Can't resolve datatype: {arg}")

        parameters.append(ParameterDefinitionImpl(None, data_type, None))

    def clean_up_signature_text(self, signature_text: str, original_signature: 'FunctionSignature') -> str:
        return self.replace_data_type_if_needed(signature_text, original_signature.get_return_type(), self.REPLACEMENT_DT_NAME) + \
               ''.join([self.replace_name_if_needed(arg.strip()) for arg in [signature_text] if not isinstance(original_signature, FunctionDefinitionDataType)])

    def replace_data_type_if_needed(self, text: str, data_type: 'DataType', replacement_name: str) -> str:
        return self.substitute(text, data_type.name, replacement_name)

    @staticmethod
    def substitute(text: str, search_string: str, replacement_string: str) -> str:
        pattern = re.compile(re.escape(search_string))
        match = pattern.match(text)
        if not match:
            raise ValueError(f"Can't find '{search_string}' in the text")

        return pattern.sub(replacement_string, text)

    def extract_return_type(self, signature_text: str) -> 'DataType':
        start_index = signature_text.find('(')
        end_index = signature_text.find(')')
        if start_index < 0 or end_index < 0 or start_index >= end_index:
            raise ValueError("Can't find return type")

        args_list = [arg.strip() for arg in signature_text[:start_index].split()]
        name = ' '.join(args_list[-1:])
        return self.resolve_data_type(name)

    def extract_function_name(self, signature_text: str) -> str:
        start_index = signature_text.find('(')
        if start_index < 0 or not isinstance(signature_text, str):
            raise ValueError("Can't find function name")

        args_list = [arg.strip() for arg in signature_text[:start_index].split()]
        return ' '.join(args_list[-1:])

    def resolve_name(self, text: str) -> str:
        if self.name_map.get(text):
            return self.name_map[text]

        if not can_parse(text):
            raise ValueError(f"Can't parse name '{text}'")

        return text

    @staticmethod
    def can_parse(text: str) -> bool:
        return not re.search(r'[*(),]', text)

class ParserDataTypeManagerService(DataTypeQueryService):
    dt_cache = {}

    def __init__(self, service: 'DataTypeQueryService'):
        self.service = service

    def clear_cache(self) -> None:
        self.dt_cache.clear()

    @staticmethod
    def get_data_type(filter_text: str) -> 'DataType':
        data_type = self.dt_cache.get(filter_text)
        if not data_type:
            return self.service.get_data_type(filter_text)

        self.dt_cache[filter_text] = data_type

        return data_type

class DataTypeParser:
    @staticmethod
    def parse(data_type_name: str) -> 'DataType':
        # implementation intended for use with FunctionSignatureParser and underlying classes.
        pass

class ParameterDefinitionImpl(ParameterDefinition):
    def __init__(self, name: str, data_type: 'DataType', ordinal: int = 0):
        self.name = name
        self.data_type = data_type
        self.ordinal = ordinal

class FunctionDefinitionDataType:
    @staticmethod
    def get_return_type(self) -> None:
        pass

    @staticmethod
    def set_arguments(self, arguments: list['ParameterDefinition']) -> None:
        pass

    @staticmethod
    def set_var_args(self, has_var_args: bool) -> None:
        pass

class ParameterDefinition:
    pass

class Dynamic(DataType):
    pass

class FactoryDataType(DataType):
    pass

class Pointer(DataType):
    pass

class Array(DataType):
    pass

class TypeDef(DataType):
    pass
```

Please note that the above Python code is not a direct translation of your Java code. It's more like an interpretation, as some parts might be missing or different due to differences in languages and paradigms.

Also, please note that I've used `re` module for regular expression operations which you would need to import at the beginning of your script: `import re`.