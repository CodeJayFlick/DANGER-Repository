Here is a translation of the provided Java code into equivalent Python:

```Python
class FunctionSignatureTableColumn:
    INLINE = "inline"
    THUNK = "thunk"
    NORETURN = "noreturn"

    def __init__(self):
        self.renderer = SignatureRenderer()

    @property
    def column_name(self):
        return "Function Signature"

    def get_column_display_name(self, settings):
        return self.column_name

    def get_value(self, row_object: 'Function', settings, program, service_provider) -> 'Function':
        if not row_object:
            return None
        return row_object

    @property
    def column_renderer(self):
        return self.renderer

    def get_column_preferred_width(self):
        # a reasonable default based upon other standard columns, like label and address columns
        return 200

class SignatureRenderer:
    def inline(self, function: 'Function', settings, buffy) -> None:
        if not function.is_inline():
            return
        show_inline = INLINE in [setting for setting in settings]
        if not show_inline:
            return
        buffy.append("inline ")

    def noreturn(self, function: 'Function', settings, buffy) -> None:
        if not function.has_no_return():
            return
        show_noreturn = NORETURN in [setting for setting in settings]
        if not show_noreturn:
            return
        buffy.append("noreturn ")

    def thunk(self, function: 'Function', settings, buffy) -> None:
        if not function.is_thunk():
            return
        show_thunk = THUNK in [setting for setting in settings]
        if not show_thunk:
            return
        buffy.append("thunk ")

    def get_signature(self, function: 'Function', settings) -> str:
        if not function:
            return None

        buffy = StringBuilder()

        self.inline(function, settings, buffy)
        self.thunk(function, settings, buffy)
        self.noreturn(function, settings, buffy)

        prototype_string = function.get_prototype_string(False, False)
        buffy.append(prototype_string)
        return str(buffy)

    def get_table_cell_renderer_component(self, data) -> 'Component':
        label = super().get_table_cell_renderer_component(data)
        value = data['value']
        settings = data['settings']

        label.set_font(get_fixed_width_font())

        function = Function(value)
        label.set_text(self.get_signature(function, settings))

        return label

    def get_filter_string(self, t: 'Function', settings) -> str:
        return self.get_signature(t, settings)

```

This Python code is equivalent to the provided Java code. It defines a `FunctionSignatureTableColumn` class with methods for getting column name, display name, value, and renderer. The `SignatureRenderer` class has methods for rendering function signatures based on inline, thunk, or no return settings.