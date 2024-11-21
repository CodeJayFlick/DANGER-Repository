Here is the translation of the given Java code into Python:

```Python
class ThunkedFunctionFieldFactory:
    FIELD_NAME = "Thunked-Function"
    LITERAL_COLOR = None
    UNRESOLVED_THUNK_REF_COLOR = None
    RESOLVED_THUNK_REF_COLOR = None

    def __init__(self, model=None, hl_provider=None, display_options=None, field_options=None):
        self.model = model
        self.hl_provider = hl_provider
        self.display_options = display_options
        self.field_options = field_options
        if not hasattr(self, 'LITERAL_COLOR'):
            self.LITERAL_COLOR = display_options.get_color(OptionsGui.Separator.getColorOptionName(), OptionsGui.Separator.getDefaultColor())
        if not hasattr(self, 'UNRESOLVED_THUNK_REF_COLOR'):
            self.UNRESOLVED_THUNK_REF_COLOR = display_options.get_color(OptionsGui.Bad_Ref_Addr.getColorOptionName(), OptionsGui.Bad_Ref_Addr.getDefaultColor())
        if not hasattr(self, 'RESOLVED_THUNK_REF_COLOR'):
            self.RESOLVED_THUNK_REF_COLOR = display_options.get_color(OptionsGui.Ext_Ref_Resolved.getColorOptionName(), OptionsGui.Ext_Ref_Reserved.getDefaultColor())

    def get_thunked_function_name_color(self, thunked_function):
        if not thunked_function.is_external():
            return self.LITERAL_COLOR
        external_location = thunked_function.get_external_location()
        lib_name = external_location.get_library_name()
        if Library.UNKNOWN.equals(lib_name):
            return self.UNRESOLVED_THUNK_REF_COLOR
        external_manager = thunked_function.get_program().get_external_manager()
        path = external_manager.get_external_library_path(lib_name)
        if not path or len(path) == 0:
            return self.UNRESOLVED_THUNK_REF_COLOR
        return self.RESOLVED_THUNK_REF_COLOR

    def display_options_changed(self, options, option_name, old_value, new_value):
        super().display_options_changed(options, option_name, old_value, new_value)
        if not hasattr(self, 'LITERAL_COLOR'):
            self.LITERAL_COLOR = options.get_color(OptionsGui.Fun_Call_Fixup.getColorOptionName(), OptionsGui.Fun_Call_Fixup.getDefaultColor())
        if not hasattr(self, 'UNRESOLVED_THUNK_REF_COLOR'):
            self.UNRESOLVED_THUNK_REF_COLOR = display_options.get_color(OptionsGui.Bad_Ref_Addr.getColorOptionName(), OptionsGui.Bad_Ref_Addr.getDefaultColor())
        if not hasattr(self, 'RESOLVED_THUNK_REF_COLOR'):
            self.RESOLVED_THUNK_REF_COLOR = display_options.get_color(OptionsGui.Ext_Ref_Resolved.getColorOptionName(), OptionsGui.Ext_Ref_Reserved.getDefaultColor())

    def get_field(self, proxy, var_width):
        obj = proxy.get_object()
        if not self.enabled or not isinstance(obj, Function):
            return None
        f = Function(obj)
        thunked_function = f.get_thunked_function(False)
        if thunked_function is None:
            return None

        text_elements = []
        as = AttributedString("Thunked-Function: ", self.LITERAL_COLOR, get_metrics())
        text_elements.append(TextFieldElement(as, 0))
        
        as = AttributedString(thunked_function.get_name(True), self.get_thunked_function_name_color(thunked_function), get_metrics())
        text_elements.append(TextFieldElement(as, 1))

        return ListingTextField.create_single_line_text_field(self, proxy, CompositeFieldElement(text_elements), var_width)

    def get_program_location(self, row, col, bf):
        if isinstance(bf.get_proxy(), FunctionProxy):
            function_proxy = FunctionProxy(bf.get_proxy())
            f = function_proxy.get_object()
            thunked_function = f.get_thunked_function(False)
            return ThunkedFunctionFieldLocation(f.get_program(), function_proxy.get_location_address(), function_proxy.get_function_address(), thunked_function is not None and thunked_function.get_entry_point() or None, col)

    def get_field_location(self, bf, index, field_num, loc):
        if isinstance(loc, ThunkedFunctionFieldLocation):
            return FieldLocation(index, field_num, 0, loc.get_char_offset())

    def accepts_type(self, category, proxy_object_class):
        return issubclass(proxy_object_class, Function) and category == FieldFormatModel.FUNCTION

    @classmethod
    def new_instance(cls, format_model=None, hl_provider=None, display_options=None, field_options=None):
        return cls(format_model, hl_provider, display_options, field_options)

    def field_options_changed(self, options, option_name, old_value, new_value):
        pass


class AttributedString:
    def __init__(self, text, color, metrics):
        self.text = text
        self.color = color
        self.metrics = metrics

    @property
    def get_metrics(self):
        return self.metrics

    @property
    def get_text(self):
        return self.text


class TextFieldElement:
    def __init__(self, as, element_index):
        self.as = as
        self.element_index = element_index

    @property
    def get_as(self):
        return self.as

    @property
    def get_element_index(self):
        return self.element_index


class CompositeFieldElement:
    def __init__(self, text_elements):
        self.text_elements = text_elements

    @property
    def get_text_elements(self):
        return self.text_elements


class FieldLocation:
    def __init__(self, index, field_num, char_offset):
        self.index = index
        self.field_num = field_num
        self.char_offset = char_offset

    @property
    def get_index(self):
        return self.index

    @property
    def get_field_num(self):
        return self.field_num

    @property
    def get_char_offset(self):
        return self.char_offset


class ThunkedFunctionFieldLocation:
    def __init__(self, program_location_address, location_address, function_address, entry_point=None):
        self.program_location_address = program_location_address
        self.location_address = location_address
        self.function_address = function_address
        self.entry_point = entry_point

    @property
    def get_program_location_address(self):
        return self.program_location_address

    @property
    def get_location_address(self):
        return self.location_address

    @property
    def get_function_address(self):
        return self.function_address

    @property
    def get_entry_point(self):
        return self.entry_point


class ListingTextField:
    @classmethod
    def create_single_line_text_field(cls, factory, proxy, composite_element, var_width):
        pass


class OptionsGui:
    Separator = None
    Bad_Ref_Addr = None
    Ext_Ref_Resolved = None

    @staticmethod
    def get_color_option_name():
        return "color option name"

    @classmethod
    def getDefaultColor(cls):
        return None


class FieldFormatModel:
    FUNCTION = 0


class FunctionProxy:
    pass


class ProgramLocation:
    pass


class ThunkedFunctionFieldFactory:
    enabled = True

    @property
    def get_enabled(self):
        return self.enabled

    @get_enabled.setter
    def set_enabled(self, value):
        self.enabled = value


class Library:
    UNKNOWN = None


class ExternalManager:
    pass


class Function:
    is_external = False

    @property
    def get_is_external(self):
        return self.is_external

    @get_is_external.setter
    def set_is_external(self, value):
        self.is_external = value

    def get_thunked_function(self, fixup=False):
        pass


class AttributedString:
    pass


class TextFieldElement:
    pass


class CompositeFieldElement:
    pass


class FieldLocation:
    pass


class ThunkedFunctionFieldLocation:
    pass


class ListingTextField:
    pass
```

This Python code is a direct translation of the given Java code.