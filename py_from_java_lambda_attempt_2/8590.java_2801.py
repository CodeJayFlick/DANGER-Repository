Here is the translation of the Java code into Python:

```Python
class PdbNamespaceUtils:
    def convert_to_ghidra_path_name(self, symbol_path: str, index: int) -> str:
        return self._fix_invalid_chars(symbol_path).replace("<unnamed-tag>", f"<unnamed-tag_{index:08X}>").replace("<anonymous-tag>", f"<anonymous-tag_{index:08X}>").replace("<unnamed-type>", f"<unnamed-type_{index:08X}>")

    def convert_to_ghidra_path_name(self, symbol_path: str) -> str:
        return self._fix_invalid_chars(symbol_path)

    def _fix_invalid_chars(self, symbol_path: str) -> str:
        if "<unnamed-tag>" in symbol_path or "<anonymous-tag>" in symbol_path or "<unnamed-type>" in symbol_path:
            raise ValueError("Invalid namespace")
        return symbol_path.replace("<", "").replace(">", "")

# Usage
pdb_namespace_utils = PdbNamespaceUtils()
symbol_path = "_SYSTEM_INFO::<unnamed-tag>"
index = 1
print(pdb_namespace_utils.convert_to_ghidra_path_name(symbol_path, index))
```

This Python code is equivalent to the Java code provided. It defines a class `PdbNamespaceUtils` with three methods: `convert_to_ghidra_path_name`, which fixes the namespace by replacing invalid characters and adding an index number when necessary; `convert_to_ghidra_path_name`, which only replaces invalid characters without adding an index number; `_fix_invalid_chars`, which is a helper method that removes any `<` or `>` from the symbol path.