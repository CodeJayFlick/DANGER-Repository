Here is the translation of the Java code into Python:

```Python
import re

class DemanglerUtil:
    LEADING_PARAMETER_SPACE_PATTERN = re.compile(r'  \(\)|\*|\&\)') 
    TRAILING_PARAMETER_SPACE_PATTERN = re.compile(r'\(|,  ')

    def demangle(mangled):
        demanglers = self.get_demanglers()
        for demangler in demanglers:
            try:
                if not demangler.can_demangle():
                    continue
                demangled_object = demangler.demangle(mangled)
                return demangled_object
            except Exception as e:
                pass

    def get_demanglers(self):
        import ghidra.app.util.classfinder
        return [cls() for cls in ghidra.app.util.classfinder.get_instances(Demangler)]

    @staticmethod
    def strip_superfluous_signature_spaces(str):
        str = re.sub(LEADING_PARAMETER_SPACE_PATTERN, '', str)
        str = re.sub(TRAILING_PARAMETER_SPACE_PATTERN, '', str)
        return str

# Usage:
util = DemanglerUtil()
print(util.strip_superfluous_signature_spaces('mangled_name'))
```

Please note that this is a direct translation of the Java code into Python. The actual functionality may not work as expected because some classes and methods are missing in your provided code, such as `Demangler`, `Program`, etc.