Here is the translation of the given Java code into Python:

```Python
class ARM_ElfProgramHeaderConstants:
    PT_ARM_ARCHEXT_FMTMSK = 0xff000000
    PT_ARM_ARCHEXT_PROFMSK = 0x00ff0000
    PT_ARM_ARCHEXT_ARCHMSK = 0x000000ff

    PT_ARM_ARCHEXT_FMT_OS = 0x00000000
    PT_ARM_ARCHEXT_FMT_ABI = 0x01000000

    PT_ARM_ARCHEXT_PROF_NONE = 0x0
    PT_ARM_ARCHEXT_PROF_ARM = 'A' << 16
    PT_ARM_ARCHEXT_PROF_RT = 'R' << 16
    PT_ARM_ARCHEXT_PROF_MC = 'M' << 16
    PT_ARM_ARCHEXT_PROF_CLASSIC = 'S' << 16

    PT_ARM_ARCHEXT_ARCH_UNKN = 0x00
    PT_ARM_ARCHEXT_ARCH_v4 = 0x01
    PT_ARM_ARCHEXT_ARCH_v4T = 0x02
    PT_ARM_ARCHEXT_ARCH_v5T = 0x03
    PT_ARM_ARCHEXT_ARCH_v5TE = 0x04
    PT_ARM_ARCHEXT_ARCH_v5TEJ = 0x05
    PT_ARM_ARCHEXT_ARCH_v6 = 0x06
    PT_ARM_ARCHEXT_ARCH_v6KZ = 0x07
    PT_ARM_ARCHEXT_ARCH_v6T2 = 0x08
    PT_ARM_ARCHEXT_ARCH_v6K = 0x09
    PT_ARM_ARCHEXT_ARCH_v7 = 0x0A
    PT_ARM_ARCHEXT_ARCH_v6M = 0x0B
    PT_ARM_ARCHEXT_ARCH_v6SM = 0x0C
    PT_ARM_ARCHEXT_ARCH_v7EM = 0x0D

    EF_ARM_EABIMASK = 0xFF000000
    EF_ARM_BE8 = 0x00800000
```

Note that Python does not have direct support for Java's `public static final` keywords. In this translation, I've simply defined the constants as class-level variables in a Python class.