import ghidra_scripting as gs

class ConvertDotToDashInAutoAnalysisLabels(gs.GhidraScript):
    def run(self):
        symbol_table = self.current_program.get_symbol_table()
        iterator = symbol_table.get_defined_symbols()

        while iterator.has_next():
            symbol = iterator.next()
            name = symbol.name
            if (symbol.source == gs.SourceType.ANALYSIS and 
                not name.startswith("u_") and 
                not name.startswith("s_")):
                new_name = name.replace('.', '_')
                symbol.set_name(new_name, gs.SourceType.ANALYSIS)

if __name__ == "__main__":
    script = ConvertDotToDashInAutoAnalysisLabels()
    script.run()
