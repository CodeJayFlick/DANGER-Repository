Here is the translation of the Java code to Python:
```python
class DataLanguageHelper:
    @staticmethod
    def get_language(language_service: 'ghidra.program.model.lang.LanguageService', 
                     pointer_size: int, 
                     is_big_endian: bool) -> tuple:
        if not (pointer_size in [16, 32, 64]):
            raise LanguageNotFoundException(f"Unable to locate DATA language for pointer size: {pointer_size}")

        processor = ghidra.program.model.lang.Processor.find_or_create("DATA")
        endian = "BIG" if is_big_endian else "LITTLE"
        size = 64
        variant = "default"
        compiler_spec_id = f"pointer{pointer_size}"

        query = ghidra.program.model.lang.LanguageCompilerSpecQuery(
            processor, 
            endian, 
            size, 
            variant, 
            compiler_spec_id
        )

        pairs = language_service.get_language_compiler_spec_pairs(query)

        if len(pairs) > 0:
            if len(pairs) > 1:
                raise LanguageNotFoundException("Too many DATA languages")
            pair = pairs[0]
            return (pair.language_id, pair.compiler_spec_id)
        else:
            raise LanguageNotFoundException("Unable to locate DATA language")

class LanguageNotFoundException(Exception):
    pass
```
Note that I've used type hints for the function parameters and variables where possible. Additionally, I've replaced the `throws` clause with a Python-style exception handling mechanism using the `raise` statement.

Also, please note that this is just one way to translate Java code to Python, and there may be other valid translations depending on the specific requirements of your project.