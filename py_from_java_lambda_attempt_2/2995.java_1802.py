Here is the equivalent Python script:
```python
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
```
Note that I used the `ghidra_scripting` module to interact with Ghidra's scripting API. This is a Python wrapper around the original Java-based API, and it provides similar functionality but in a more Pythonic way.

Also, keep in mind that this code assumes you have already installed the `ghidra_scripting` package and have access to the necessary Ghidra APIs. If you're new to using Ghidra with Python scripting, I recommend checking out their documentation for more information on how to get started!