import ghidra_program_database_symbol as gpbs
from ghidra_program_model_address import Address
from ghidra_program_model_listing import Program
from ghidra_program_model_symbol import Symbol
from ghidra_program_model_symbol_table import SymbolTable

class LabelMarkupUtils:

    @staticmethod
    def remove_all_labels(destination_program: Program, address: Address) -> None:
        symbol_table = destination_program.get_symbol_table()
        symbols = symbol_table.get_symbols(address)
        for symbol in symbols:
            if isinstance(symbol, gpbs.FunctionSymbol):
                continue
            symbol_table.remove_special(symbol)

# Example usage:
destination_program = ...  # create a Program object
address = Address(...)  # create an Address object
LabelMarkupUtils.remove_all_labels(destination_program, address)
