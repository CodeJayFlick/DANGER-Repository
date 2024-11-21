Here is the translation of the Java code into Python:

```Python
class DyldArchitecture:
    DYLD_V1_SIGNATURE_PREFIX = "dyld_v1"
    DYLD_V1_SIGNATURE_LEN = 0x10

    X86 = DyldArchitecture(CpuTypes.CPU_TYPE_X86, CpuSubTypes.CPU_SUBTYPE_MULTIPLE,
                            f"{DYLD_V1_SIGNATURE_PREFIX} i386", "i386", Endian.LITTLE)
    X86_64 = DyldArchitecture(CpuTypes.CPU_TYPE_X86_64, CpuSubTypes.CPU_SUBTYPE_MULTIPLE,
                              f"{DYLD_V1_SIGNATURE_PREFIX} x86_64", "x86_64", Endian.LITTLE)
    X86_64h = DyldArchitecture(CpuTypes.CPU_TYPE_X86_64, CpuSubTypes.CPU_SUBTYPE_MULTIPLE,
                               f"{DYLD_V1_SIGNATURE_PREFIX} x86_64h", "x86_64", Endian.LITTLE)
    POWERPC = DyldArchitecture(CpuTypes.CPU_TYPE_POWERPC, CpuSubTypes.CPU_SUBTYPE_MULTIPLE,
                                f"{DYLD_V1_SIGNATURE_PREFIX} ppc", "rosetta", Endian.BIG)
    ARMV6 = DyldArchitecture(CpuTypes.CPU_TYPE_ARM, CpuSubTypes.CPU_SUBTYPE_ARM_V6,
                             f"{DYLD_V1_SIGNATURE_PREFIX} armv6", "armv6", Endian.LITTLE)
    ARMV7 = DyldArchitecture(CpuTypes.CPU_TYPE_ARM, CpuSubTypes.CPU_SUBTYPE_ARM_V7,
                             f"{DYLD_V1_SIGNATURE_PREFIX} armv7", "arm7", Endian.LITTLE)
    ARMV7F = DyldArchitecture(CpuTypes.CPU_TYPE_ARM, CpuSubTypes.CPU_SUBTYPE_ARM_V7F,
                              f"{DYLD_V1_SIGNATURE_PREFIX} armv7f", "arm7", Endian.LITTLE)
    ARMV7S = DyldArchitecture(CpuTypes.CPU_TYPE_ARM, CpuSubTypes.CPU_SUBTYPE_ARM_V7S,
                              f"{DYLD_V1_SIGNATURE_PREFIX} armv7s", "arm7", Endian.LITTLE)
    ARMV7K = DyldArchitecture(CpuTypes.CPU_TYPE_ARM, CpuSubTypes.CPU_SUBTYPE_ARM_V7K,
                              f"{DYLD_V1_SIGNATURE_PREFIX} armv7k", "arm7", Endian.LITTLE)
    ARMV8A = DyldArchitecture(CpuTypes.CPU_TYPE_ARM_64, CpuSubTypes.CPU_SUBTYPE_MULTIPLE,
                              f"{DYLD_V1_SIGNATURE_PREFIX} arm64", "AARCH64", Endian.LITTLE)
    ARMV8Ae = DyldArchitecture(CpuTypes.CPU_TYPE_ARM_64, CpuSubTypes.CPU_SUBTYPE_MULTIPLE,
                               f"{DYLD_V1_SIGNATURE_PREFIX} arm64e", "AARCH64", Endian.LITTLE)

    ARCHITECTURES = [X86, X86_64, X86_64h, POWERPC, ARMV6, ARMV7, ARMV7F, ARMV7S, ARMV7K, ARMV8A, ARMV8Ae]

    def __init__(self, cpu_type: int, cpu_subtype: int, signature: str, processor: str, endianness: Endian):
        self.cpu_type = cpu_type
        self.cpu_subtype = cpu_subtype
        self.signature = signature
        self.processor = processor
        self.endianness = endianness

    def get_cpu_type(self) -> int:
        return self.cpu_type

    def get_cpu_subtype(self) -> int:
        return self.cpu_subtype

    def get_signature(self) -> str:
        return self.signature

    def get_processor(self) -> str:
        return self.processor

    def get_endianness(self) -> Endian:
        return self.endianness

    @property
    def __str__(self):
        return self.signature

    def get_language_compiler_spec_pair(self, language_service: 'LanguageService') -> tuple:
        if self == X86:
            return (new LanguageID("x86:LE:32:default"), new CompilerSpecID("gcc"))
        elif self in [X86_64, X86_64h]:
            return (new LanguageID("x86:LE:64:default"), new CompilerSpecID("gcc"))
        elif self == POWERPC:
            return (new LanguageID("PowerPC:BE:32:default"), new CompilerSpecID("macosx"))
        else:
            raise LanguageNotFoundException(f"Unable to locate language for {self}")

    @staticmethod
    def get_architecture(signature: str) -> 'DyldArchitecture':
        for architecture in ARCHITECTURES:
            if architecture.get_signature().lower() == signature.lower():
                return architecture
        return None

    @staticmethod
    def get_architecture(provider: ByteProvider, endianness: Endian = Endian.LITTLE) -> 'DyldArchitecture':
        signature_bytes = provider.read_bytes(0, Dyld_V1_SIGNATURE_LEN)
        signature = ''.join(map(chr, signature_bytes))
        return DyldArchitecture.get_architecture(signature)

class LanguageCompilerSpecPair:
    def __init__(self, language_id: 'LanguageID', compiler_spec_id: 'CompilerSpecID'):
        self.language_id = language_id
        self.compiler_spec_id = compiler_spec_id

    @property
    def __str__(self):
        return f"{self.language_id} - {self.compiler_spec_id}"

class Endian:
    LITTLE = 0
    BIG = 1