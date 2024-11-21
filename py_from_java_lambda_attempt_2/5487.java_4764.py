Here is a translation of the provided Java code into equivalent Python:

```Python
class FunctionSignatureSourceFieldFactory:
    FIELD_NAME = "Signature Source"
    
    def __init__(self):
        super().__init__(FIELD_NAME)

    def __init__(self, model: 'FieldFormatModel', hl_provider: 'HighlightProvider',
                 display_options: dict, field_options: dict):
        super().__init__(model, hl_provider, display_options, field_options)
        
        self.literal_color = display_options.get('separator.color', Color.BLACK)

    @property
    def enabled(self) -> bool:
        return True

    def get_field(self, proxy_obj: 'ProxyObj', var_width: int):
        if not self.enabled:
            return None
        
        if isinstance(proxy_obj, FunctionProxy):
            function_proxy = proxy_obj
            function = function_proxy.get_object()
            source_type = function.get_signature_source()
            source_str = f"<{source_type}>"  # equivalent to "<" + str(source) + ">"
            
            attributed_string = AttributedString(source_str, self.literal_color)
            return ListingTextField.create_single_line_text_field(self,
                                                                  proxy_obj,
                                                                  TextFieldElement(attributed_string),
                                                                  var_width)

    def get_program_location(self, row: int, col: int, listing_field: 'ListingField') -> ProgramLocation:
        if isinstance(listing_field.get_proxy(), FunctionProxy):
            function_proxy = listing_field.get_proxy()
            function = function_proxy.get_object()
            
            return FunctionSignatureSourceFieldLocation(function.get_program(),
                                                         function_proxy.get_location_address(),
                                                         function_proxy.get_function_address(),
                                                         str(function.get_signature_source()),
                                                         col)

    def get_field_location(self, listing_field: 'ListingField', index: int, field_num: int,
                            program_location: ProgramLocation) -> FieldLocation:
        if isinstance(program_location, FunctionSignatureSourceFieldLocation):
            sig_source_loc = program_location
            return FieldLocation(index, field_num, 0, sig_source_loc.get_char_offset())

    def accepts_type(self, category: int, proxy_object_class: type) -> bool:
        return issubclass(proxy_object_class, Function) and category == 'FUNCTION'

    @classmethod
    def new_instance(cls):
        return cls()

    def get_default_color(self) -> Color:
        return OptionsGui.Separator.default_color

class AttributedString(str): pass