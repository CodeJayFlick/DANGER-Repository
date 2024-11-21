import ghidra_script

class Update8051:
    SFR = "SFR"
    BITS = "BITS"
    SFR_BITS = "SFR-BITS"

    def run(self):
        if current_program.get_address_factory().get_num_address_spaces() == 1:
            print("Program is not an 8051")
            return

        symbol_table = current_program.get_symbol_table()
        for symbol in symbol_table.get_defined_symbols():
            space_name = symbol.get_address().get_address_space().name
            if space_name in [self.SFR, self.BITS, self.SFR_BITS]:
                symbol.set_source(ghidra_script.SourceType.IMPORTED)
                print(f"Changed source on {symbol.name}")
        else:
            print("No address spaces found for", self.SFR, ",", self.BITS, ",", self.SFR_BITS)

    def __init__(self):
        pass

# This is the main function that will be called when this script is run
def main():
    update8051 = Update8051()
    try:
        update8051.run()
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()

