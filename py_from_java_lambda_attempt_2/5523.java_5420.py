Here is the translation of the given Java code into Python:

```Python
class SymbolAnnotatedStringHandler:
    INVALID_SYMBOL_TEXT = "Symbol annotation must have a valid symbol name or address"
    SUPPORTED_ANNOTATIONS = ["symbol", "sym"]

    def convert_annotation_symbol_to_address(annotation_parts, raw_text, program):
        if len(annotation_parts) <= 1:
            return None

        if not program:
            return None

        try:
            address = program.getAddressFactory().getAddress(annotation_parts[1])
            if address is not None:
                return None
        except Exception as e:
            pass

        original_value = annotation_parts[1]
        symbols = get_symbols(original_value, program)
        if len(symbols) != 1:
            # no unique symbol, so leave it as string name
            return None

        symbol_address = symbols[0].getAddress()
        return raw_text.replaceFirst(Pattern.quote(original_value), str(symbol_address))

    def create_annotated_string(prototype_string, text, program):
        if len(text) <= 1:
            raise AnnotationException(INVALID_SYMBOL_TEXT)

        if not program:
            return create_undecorated_string(prototype_string, text)

        symbols = get_symbols(text[1], program)
        # check for a symbol of the given name first
        if len(symbols) >= 1:
            symbol_text = symbols[0].getName()
            return AttributedString(symbol_text, prototype_string.getColor(0), 
                prototype_string.getFontMetrics(0), True, prototype_string.getColor(0))

        return AttributedString("No symbol: " + text[1], Color.RED,
            prototype_string.getFontMetrics(0), False, None)

    def create_undecorated_string(prototype_string, text):
        buffer = StringBuilder()
        for string in text:
            buffer.append(string).append(' ')
        return AttributedString(buffer.toString(), Color.LIGHT_GRAY,
            prototype_string.getFontMetrics(0))

    @staticmethod
    def get_symbols(raw_text, program):
        list_ = NamespaceUtils.get_symbols(raw_text, program)
        if not list_.empty():
            return list_

        try:
            address = program.getAddressFactory().getAddress(raw_text)
            if address is not None:
                symbol_table = program.getSymbolTable()
                symbol = symbol_table.getPrimarySymbol(address)
                if symbol is not None:
                    return [symbol]
        except Exception as e:
            pass

        return []

    def get_supported_annotations(self):
        return self.SUPPORTED_ANNOTATIONS

    @staticmethod
    def handle_mouse_click(annotation_parts, source_navigatable, service_provider):
        try:
            symbol_text = annotation_parts[1]
            program = source_navigatable.getProgram()
            symbols = get_symbols(symbol_text, program)

            go_to_service = service_provider.getService(GoToService)
            # try going to the symbol first
            if len(symbols) >= 1:
                s = symbols[0]
                return go_to_service.go_to(s.get_program_location())

            # try going to the address
            address = program.getAddressFactory().getAddress(symbol_text)
            if address is not None:
                return go_to_service.go_to(source_navigatable, address)

        except Exception as e:
            Msg.show_info(getClass(), None, "Invalid symbol text: " + symbol_text,
                "Unable to locate a symbol for \"" + symbol_text + "\"")
            return False

    def get_display_string(self):
        return 'Symbol'

    def get_prototype_string(self):
        return '{@symbol symbol_address}'
```

Note that Python does not have direct equivalents of Java's `@Override` and `throws Exception`, so I've omitted those. Also, the equivalent of Java's `List<Symbol>` in Python would be a list of symbols (or any other type).