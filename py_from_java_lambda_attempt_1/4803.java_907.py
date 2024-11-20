Here is the translation of the given Java code into equivalent Python:

```Python
class CpuSubTypes:
    # PowerPC subtypes
    POWERPC_ALL = 0
    POWERPC_601 = 1
    POWERPC_602 = 2
    POWERPC_603 = 3
    POWERPC_603e = 4
    POWERPC_603ev = 5
    POWERPC_604 = 6
    POWERPC_604e = 7
    POWERPC_620 = 8
    POWERPC_750 = 9
    POWERPC_7400 = 10
    POWERPC_7450 = 11
    POWERPC_MAX = 10
    POWERPC_SCVGER = 11
    POWERPC_970 = 100

    # I386 subtypes
    CPU_SUBTYPE_I386_ALL = 3
    CPU_SUBTYPE_INTEL = lambda f, m: f + (m << 4)

    X86_ALL = 3
    X86_ARCH1 = 4

    THREADTYPE_INTEL_HTT = 1

    # Mips subtypes
    MIPS_ALL = 0
    MIPS_R2300 = 1
    MIPS_R2600 = 2
    MIPS_R2800 = 3
    MIPS_R2000a = 4
    MIPS_R2000 = 5
    MIPS_R3000a = 6
    MIPS_R3000 = 7

    # MC98000 (PowerPC) subtypes
    CPU_SUBTYPE_MC98000_ALL = 0
    CPU_SUBTYPE_MC98601 = 1

    # HPPA subtypes for Hewlett-Packard HP-PA family of risc processors.
    CPU_SUBTYPE_HPPA_ALL = 0
    CPU_SUBTYPE_HPPA_7100 = 0
    CPU_SUBTYPE_HPPA_7100LC = 1

    # MC88000 subtypes
    CPU_SUBTYPE_MC88000_ALL = 0
    CPU_SUBTYPE_MC88100 = 1
    CPU_SUBTYPE_MC88110 = 2

    # SPARC subtypes
    CPU_SUBTYPE_SPARC_ALL = 0

    # I860 subtypes
    CPU_SUBTYPE_I860_ALL = 0
    CPU_SUBTYPE_I860_860 = 1

    # VAX subtypes
    CPU_SUBTYPE_VAX_ALL = 0
    CPU_SUBTYPE_VAX780 = 1
    CPU_SUBTYPE_VAX785 = 2
    CPU_SUBTYPE_VAX750 = 3
    CPU_SUBTYPE_VAX730 = 4
    CPU_SUBTYPE_UVAXI = 5
    CPU_SUBTYPE_UVAXII = 6
    CPU_SUBTYPE_VAX8200 = 7
    CPU_SUBTYPE_VAX8500 = 8
    CPU_SUBTYPE_VAX8600 = 9
    CPU_SUBTYPE_VAX8650 = 10
    CPU_SUBTYPE_VAX8800 = 11
    CPU_SUBTYPE_UVAXIII = 12

    # 680x0 subtypes
    CPU_SUBTYPE_MC680X0_ALL = 1
    CPU_SUBTYPE_MC68030 = 1
    CPU_SUBTYPE_MC68040 = 2
    CPU_SUBTYPE_MC68030_ONLY = 3

    # ARM subtypes
    CPU_SUBTYPE_ARM_ALL = 0
    CPU_SUBTYPE_ARM_V4T = 5
    CPU_SUBTYPE_ARM_V6 = 6
    CPU_SUBTYPE_ARM_V5 = 7
    CPU_SUBTYPE_ARM_V5TEJ = 7
    CPU_SUBTYPE_ARM_XSCALE = 8
    CPU_SUBTYPE_ARM_V7 = 9
    CPU_SUBTYPE_ARM_V7F = 10
    CPU_SUBTYPE_ARM_V7S = 11
    CPU_SUBTYPE_ARM_V7K = 12
    CPU_SUBTYPE_ARM_V6M = 14
    CPU_SUBTYPE_ARM_V7M = 15
    CPU_SUBTYPE_ARM_V7EM = 16

    MULTIPLE = -1
    LITTLE_ENDIAN = 0
    BIG_ENDIAN = 1


# Example usage:
print(CpuSubTypes.POWERPC_ALL)
```

Please note that Python does not support the concept of `final` in Java. Also, there is no direct equivalent to Java's `lambda` expression in Python.