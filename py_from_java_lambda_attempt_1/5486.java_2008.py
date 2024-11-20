Here is the translation of the Java code into Python:

```Python
class FunctionSignatureFieldFactory:
    def __init__(self):
        pass

    @staticmethod
    def getFunctionNameColor(function):
        if function.isThunk():
            return "unresolved thunk ref color"
        else:
            return "function name color"

    @staticmethod
    def getFieldLocation(bf, index, field_num, loc):
        if isinstance(loc, FunctionSignatureFieldLocation):
            signature_location = loc
            if signature_location.is_field_based_positioning():
                return FieldLocation(index, field_num, 0, signature_location.get_char_offset())
        return None

    @staticmethod
    def getFunctionSignatureElement(elements, element_class, class_index):
        character_count = 0
        for i in range(len(elements)):
            if isinstance(elements[i], element_class) and i == class_index:
                return character_count
            character_count += elements[i].get_text().length()
        return 0

    @staticmethod
    def getFieldElements(bf):
        text_field = bf
        field_elements = []
        for row in range(text_field.get_num_rows()):
            previous_field_element = None
            num_columns = text_field.get_num_cols(row)
            for col in range(num_columns):
                field_element = text_field.get_field_element(row, col)
                if field_element is not None:
                    if field_element != previous_field_element:
                        field_elements.append(field_element)
                    previous_field_element = field_element
        return field_elements

    @staticmethod
    def accepts_type(category, proxy_object_class):
        if FunctionSignatureFieldFactory.is_function_signature_category(category) and isinstance(proxy_object_class, type) and issubclass(proxy_object_class, function_proxy):
            return True
        else:
            return False

class FunctionSignatureFieldElement:
    def __init__(self, as, row, column, signature_index):
        self.as = as
        self.row = row
        self.column = column
        self.signature_index = signature_index

    @staticmethod
    def get_program_location(function_proxy, signature, row_in_field, column_in_row):
        function = function_proxy.get_object()
        signature_index = FunctionSignatureFieldFactory.get_function_signature_element(FunctionSignatureFieldFactory.getFieldElements(signature), type("FunctionProxy"), 0)
        return ProgramLocation(function.get_program(), function_proxy.get_location_address(), function_proxy.get_function_address(), signature_index, signature)

    @staticmethod
    def create_element(as, row, column):
        return FunctionSignatureFieldElement(as, row, column, self.signature_index)

class FunctionReturnTypeFieldElement(FunctionSignatureFieldElement):
    pass

class FunctionThunkFieldElement(FunctionSignatureFieldElement):
    pass

# TODO: if we ever need a VarArgs handler, put one here
```

Note that I have not translated the entire codebase.