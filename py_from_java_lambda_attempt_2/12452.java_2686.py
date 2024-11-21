Here is the translation of the Java code to Python:
```
class ExternalLanguageCompilerSpecQuery:
    def __init__(self, external_processor_name: str, external_tool: str,
                 endian: int, size: int, compiler_spec_id: object):
        self.external_processor_name = external_processor_name
        self.external_tool = external_tool
        self.endian = endian
        self.size = size
        self.compiler_spec_id = compiler_spec_id

    def __str__(self) -> str:
        return f"externalProcessorName={self.external_processor_name}; " \
               f"externalTool={self.external_tool}; " \
               f"endian={self.endian}; " \
               f"size={self.size}; " \
               f"compiler={self.compiler_spec_id}"
```
Note that I used the following Python features to translate the Java code:

* Class definition: `class ExternalLanguageCompilerSpecQuery:` instead of `public class ...`.
* Constructor (initializer): `__init__(...)` instead of a constructor method.
* Attribute assignment: `self.external_processor_name = external_processor_name` instead of `this.externalProcessorName = externalProcessorName;`
* String formatting: `f"..."` instead of concatenating strings with `+`.

I also removed the Java-specific annotations (e.g., `@Override`) and type declarations, as they are not necessary in Python.