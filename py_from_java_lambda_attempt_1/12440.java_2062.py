Here is the translation of the given Java code into Python:

```Python
class BasicLanguageDescription:
    def __init__(self, language_id, processor, endian, instruction_endian, size, variant, description, version, minor_version, deprecated):
        self.language_id = language_id
        self.processor = processor
        self.endian = endian
        self.instruction_endian = instruction_endian
        self.size = size
        self.variant = variant
        self.description = description
        self.version = version
        self.minor_version = minor_version
        self.deprecated = deprecated

    def __hash__(self):
        return hash((self.language_id, self.processor, self.endian, self.instruction_endian, self.size, self.variant))

    def __eq__(self, other):
        if not isinstance(other, BasicLanguageDescription):
            return False
        return (self.language_id == other.language_id and 
                self.processor == other.processor and 
                self.endian == other.endian and 
                self.instruction_endian == other.instruction_endian and 
                self.size == other.size and 
                self.variant == other.variant)

    def get_description(self):
        return self.description

    def get_endian(self):
        return self.endian

    def get_instruction_endian(self):
        return self.instruction_endian

    def get_language_id(self):
        return self.language_id

    def get_minor_version(self):
        return self.minor_version

    def get_version(self):
        return self.version

    def get_processor(self):
        return self.processor

    def get_size(self):
        return self.size

    def get_variant(self):
        return self.variant

    def is_deprecated(self):
        return self.deprecated

class CompilerSpecDescription:
    pass  # This class does not have any methods or attributes in the given Java code.

def main():
    language_id = "your_language_id"
    processor = "your_processor"
    endian = "your_endian"
    instruction_endian = "your_instruction_endian"
    size = 1
    variant = "your_variant"
    description = "your_description"
    version = 1.0
    minor_version = 1

    basic_language_description = BasicLanguageDescription(language_id, processor, endian, instruction_endian, size, variant, description, version, minor_version)

if __name__ == "__main__":
    main()
```

Note: The given Java code does not have any methods or attributes related to `CompilerSpecID`, `CompilerSpecNotFoundException` and `Map<String, List<String>> externalNames`. Therefore, I did not translate those parts into Python.