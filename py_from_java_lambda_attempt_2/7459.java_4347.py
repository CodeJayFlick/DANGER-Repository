Here is the translation of the given Java code into Python:

```Python
class MacosxLanguageHelper:
    def get_language_compiler_spec_pair(self, language_service: object, cpu_type: int, cpu_subtype: int) -> tuple:
        arm = None
        arm64 = None
        x86 = None
        powerpc = None

        if cpu_type == 7:  # CPU_ETYPE_ARM
            processor = "ARM"
            endian = "LITTLE"
            variant = "default"

            if cpu_subtype in [6, 15]:  # CPU_SUBTYPE_ARM_V6 or CPU_SUBTYPE_ARM_ALL
                variant = "v6"
            elif cpu_subtype == 7:  # CPU_SUBTYPE_ARM_V7
                variant = "v7"
            arm = (processor, endian, int(32), variant)

        elif cpu_type in [6, 64]:  # CPU_ETYPE_X86 or CPU_ETYPE_X86_64
            processor = "x86"
            endian = "LITTLE"
            size = 32 if cpu_type == 6 else 64

            compiler_spec_id = "gcc"

            arm64 = (processor, endian, int(size), variant)

        elif cpu_type in [17, 18]:  # CPU_ETYPE_POWERPC or CPU_ETYPE_POWERPC64
            processor = "PowerPC"
            endian = "BIG"
            size = 32 if cpu_type == 17 else 64

            compiler_spec_id = "macosx"

            powerpc = (processor, endian, int(size), variant)

        elif cpu_type == 65:  # CPU_ETYPE_ARM_64
            processor = "ARM64"
            endian = "LITTLE"
            size = 64
            variant = "v8A"

            arm64 = (processor, endian, int(size), variant)

        query = {"processor": processor, "endian": endian, "size": size, "variant": variant}

        pairs = language_service.get_language_compiler_spec_pairs(query)

        if len(pairs) > 0:
            pair = list(pairs.values())[0]
            return (pair["language_id"], pair["compiler_spec_id"])
        else:
            raise LanguageNotFoundException("Unable to locate language for {}.".format(cpu_type))

class LanguageCompilerSpecPair:
    def __init__(self, language_id: str, compiler_spec_id: str):
        self.language_id = language_id
        self.compiler_spec_id = compiler_spec_id

class LanguageNotFoundException(Exception):
    pass
```

Please note that Python does not support exact equivalent of Java's `enum` and some other constructs. Also, the code is translated as closely to the original Java code as possible but it may require adjustments based on specific requirements or constraints.