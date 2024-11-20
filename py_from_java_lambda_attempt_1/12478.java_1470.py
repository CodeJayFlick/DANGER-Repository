Here is the translation of the Java code to Python:
```
class LanguageNotFoundException(Exception):
    def __init__(self, message="Language not found"):
        super().__init__(message)

    @classmethod
    def from_language_id(cls, language_id: str) -> 'LanguageNotFoundException':
        return cls(f"Language not found for '{language_id}'")

    @classmethod
    def from_major_minor_version(cls, language_id: str, major_version: int, minor_version: int) -> 'LanguageNotFoundException':
        return cls(f"Newer version of language required (V{major_version}.{minor_version} or later) for '{language_id}'")

    @classmethod
    def from_processor(cls, processor: object) -> 'LanguageNotFoundException':
        return cls(f"Language not found for processor: {processor.__str__()}")

    @classmethod
    def from_language_compiler_spec(cls, language_id: str, compiler_spec_id: str) -> 'LanguageNotFoundException':
        return cls(f"Language/Compiler Spec not found for '{language_id}'/{compiler_spec_id}'")
```
Note that I used the `Exception` class as a base class for `LanguageNotFoundException`, since it's equivalent to Java's `IOException`. The rest of the code is translated directly from Java to Python, with some minor adjustments.