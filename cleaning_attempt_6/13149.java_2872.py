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
