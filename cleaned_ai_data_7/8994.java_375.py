class MarkupItemValueRenderer:
    def get_table_cell_renderer_component(self, data):
        super().get_table_cell_renderer_component(data)
        
        value = data.get_value()
        is_selected = data.is_selected()

        if not isinstance(value, str) and value is not None:
            raise AssertionError("Incorrect column value for the markup item value column: " + type(value).__name__)

        text = self.as_string(value)

        self.configure_renderer_for_stringable(value, text, is_selected)
        
        return this

    def as_string(self, stringable):
        if stringable is None:
            return ""

        text = stringable.get_display_string()
        if not text.strip():
            return ""  # don't add any special decoration
        else:
            return text

    def configure_renderer_for_stringable(self, stringable, text, is_selected):
        if stringable is None:
            self.set_text(text)
            return
        
        if not text.strip():
            self.set_text(text)  # don't add any special decoration
            return

        self.set_text(text)

        is_symbol = False
        if isinstance(stringable, SymbolStringable):
            is_symbol = True
        elif isinstance(stringable, FunctionNameStringable):
            is_symbol = True
        elif isinstance(stringable, MultipleSymbolStringable):
            is_symbol = True
        
        if not is_symbol:
            return

        self.set_bold()
        if not is_selected:
            self.set_foreground(Color.BLACK)

    def get_filter_string(self, t, settings):
        return self.as_string(t)
