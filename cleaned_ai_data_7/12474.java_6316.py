class LanguageCompilerSpecPair:
    def __init__(self, language_id: str, compiler_spec_id: str):
        if not language_id or not compiler_spec_id:
            raise ValueError("languageID and compilerSpecID cannot be empty")
        self.language_id = Language(language_id)
        self.compiler_spec_id = CompilerSpec(compiler_spec_id)

    def get_language(self) -> 'Language':
        return DefaultLanguageService().get_language(self.language_id)

    def get_compiler_spec(self) -> 'CompilerSpec':
        try:
            return self.get_language().get_compiler_spec_by_id(self.compiler_spec_id)
        except LanguageNotFoundException as e:
            raise CompilerSpecNotFoundException("No compiler spec found for language") from e

    def get_language_description(self) -> 'LanguageDescription':
        return DefaultLanguageService().get_language_description(self.language_id)

    def get_compiler_spec_description(self) -> 'CompilerSpecDescription':
        try:
            return self.get_language_description().get_compiler_spec_description_by_id(
                self.compiler_spec_id)
        except LanguageNotFoundException as e:
            raise CompilerSpecNotFoundException("No compiler spec description found for language") from e

class DefaultLanguageService:
    def get_language(self, language_id: str) -> 'Language':
        # implement your logic here
        pass

    def get_language_description(self, language_id: str) -> 'LanguageDescription':
        # implement your logic here
        pass


# Python doesn't have built-in support for comparable objects like Java does.
class LanguageCompilerSpecPairComparable:
    @staticmethod
    def compare(p1: 'LanguageCompilerSpecPair', p2: 'LanguageCompilerSpecPair') -> int:
        if not isinstance(p1, LanguageCompilerSpecPair) or not isinstance(p2, LanguageCompilerSpecPair):
            raise ValueError("Both objects must be of type LanguageCompilerSpecPair")
        return (p1.language_id.compare_to(p2.language_id), 
                p1.compiler_spec_id.compare_to(p2.compiler_spec_id))[0]
