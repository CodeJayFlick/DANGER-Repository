Here is the translation of the given Java code into equivalent Python:

```Python
import ghidra.app.script.GhidraScript;
from ghidra.util import Demangler;

class MicrosoftDemanglerScript(GhidraScript):
    def __init__(self):
        self.demangler = Demangler();

    def run(self) -> None:
        # demangle("??$_LStrcoll@_W@std@@YAHPB_ W000PBU_Collvec@@@Z");
        self.demangle("??$?0G@?$allocator@U_Container_proxy@std@@@std@@QAE@ABV?$allocator@G@1@@Z");

    def demangle(self, mangled: str) -> None:
        try:
            demangled = self.demangler.demangle(mangled);
            print(f"mangled {mangled}\ndemangled {demangled}");
        except Exception as e:
            print(f"Error occurred while demangling: {e}")
```

Please note that the `GhidraScript` and `Demangler` classes are not native Python modules. They seem to be part of a specific framework or library (GHIDRA) used for reverse engineering, which is why you would need to import them from their respective packages before using them in your code.