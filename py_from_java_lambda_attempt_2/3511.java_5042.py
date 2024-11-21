Here is the translation of the given Java code into equivalent Python:

```Python
class DataTypeListingHover:
    NAME = "Data Type Display"
    DESCRIPTION = f"Toggle whether data type contents are displayed in a tooltip when the mouse hovers over a data type."
    PRIORITY = 20

    def __init__(self, tool):
        self.enabled = True
        super().__init__(tool, self.PRIORITY)

    @property
    def name(self):
        return self.NAME

    @property
    def description(self):
        return self.DESCRIPTION

    @property
    def options_category(self):
        return "CATEGORY_ BROWSER_POPUPS"

    def get_hover_component(self, program: 'Program', location: 'ProgramLocation', field_location: 'FieldLocation', field: 'Field'):
        if not self.enabled or location is None:
            return None
        
        dt = None
        data_instance = None
        has_invalid_storage = False

        if isinstance(location, VariableLocation):
            var = location.get_variable()
            if var is not None:
                dt = var.get_data_type()
                has_invalid_storage = not var.is_valid()

        elif isinstance(location, MnemonicFieldLocation):
            data_instance = self.get_data_for_location(program, location)
            if data_instance is not None:
                dt = data_instance.get_data_type()
                if dt.get_length() < 0:
                    data_len = data_instance.get_length()

        elif isinstance(location, FunctionReturnTypeFieldLocation):
            dt = self.get_function_return_data_type(program, location.get_address())

        if dt is not None:
            tool_tip_text = ToolTipUtils.get_tool_tips(dt)
            if data_len is not None:
                # NOTE: "Unsized" matches with literal string in DefaultDataTypeHTMLRepresentation.build_footer()
                tool_tip_text = tool_tip_text.replace("Unsized", str(data_len))

            if data_instance is not None:
                tool_tip_text += self.get_location_supplimental_tool_tips(dt, data_instance)

            warning_msg = ""
            if has_invalid_storage:
                warning_msg += "WARNING! Invalid Storage"

            if warning_msg:
                error_text = f"<HTML><center><font color='red'>{warning_msg}!</font></center><BR>"
                tool_tip_text = tool_tip_text.replace("<HTML>", error_text)

            return self.create_tooltip_component(tool_tip_text)

        # no data type
        elif isinstance(location, EquateOperandFieldLocation):
            equate_location = location
            return self.create_equate_tool_tips_component(program, equate_location.get_equate())

    def get_data_for_location(self, program: 'Program', location: 'ProgramLocation'):
        listing = program.get_listing()
        address = location.get_address()
        data = listing.get_data_containing(address)
        if data is not None:
            return data.get_component(location.get_component_path())
        
        return None

    def get_function_return_data_type(self, program: 'Program', address):
        function_manager = program.get_function_manager()
        function = function_manager.get_function_at(address)
        if function is not None:
            return function.get_return_type()

        return None

    def create_equate_tool_tips_component(self, program: 'Program', equate: Equate):
        hover_info = StringBuilder()
        
        if equate.is_enum_based() and equate.is_valid_uuid():
            dtm = program.get_data_type_manager()
            id = equate.get_enum_uuid()
            enoom = (Enum)dtm.find_data_type_for_id(id)
            
            if enoom is not None:
                hover_info.append(f"<html>Equate value: {equate.display_value}<hr>{ToolTipUtils.get_html_representation(enoom).get_html_content_string()}</html>")
        
        else:
            hover_info.append(equate.display_value)

        return self.create_tooltip_component(hover_info.toString())

    def get_location_supplimental_tool_tips(self, dt: 'DataType', data_instance):
        result = ""
        
        if isinstance(dt, DataTypeWithCharset):
            charset = (dt).get_char_set_name(data_instance)
            result += f"<br>Charset: {charset}"

        if StringDataInstance.is_string(data_instance):
            sdi = StringDataInstance.get_string_data_instance(data_instance)

            if sdi.show_translation():
                result += f"<br>Original value: {HTMLUtilities.friendly_encode_html(sdi.string_value)}"

            if not sdi.show_translation() and sdi.translated_value is not None:
                result += f"<br>Translated value: {HTMLUtilities.friendly_encode_html(sdi.translated_value)}"

            if sdi.is_missing_null_terminator():
                result += "<br>Missing NULL terminator."

            if sdi.string_length > data_instance.length:
                result += f"<font color='red'>String exceeds data field.</font>"
        
        return result
```

Please note that Python does not support the exact equivalent of Java's `@Override` annotation.