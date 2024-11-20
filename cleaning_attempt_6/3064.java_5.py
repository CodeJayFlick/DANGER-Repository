import ghidra

class LabelDataScript:
    def __init__(self):
        self.listing = None
        self.memory = None
        self.symbol_table = None

    def run(self, monitor):
        self.listing = current_program.get_listing()
        self.memory = current_program.get_memory()
        self.symbol_table = current_program.get_symbol_table()

        data = get_first_data()
        while (data is not None) and (not monitor.is_cancelled()):
            if not data.is_pointer() and \
               not data.base_data_type.name.lower().contains("string") and \
               not data.base_data_type.name.lower().contains("unicode"):
                symbol = self.symbol_table.get_primary_symbol(data.min_address)
                if symbol is not None and ((symbol.source == SourceType.DEFAULT) or (symbol.source == SourceType.ANALYSIS)):
                    new_label = f"{data.default_label_prefix(None)}_{SymbolUtilities.replace_invalid_chars(data.default_value_representation, False)}_{data.min_address}"
                    self.symbol_table.create_label(data.min_address, new_label, SourceType.ANALYSIS)
                    print(f"{data.min_address} {new_label}")
                    if not symbol.is_primary:
                        symbol.set_primary()

            data = get_data_after(data)

def main():
    script = LabelDataScript()
    # Add your code here to use the script

if __name__ == "__main__":
    main()
