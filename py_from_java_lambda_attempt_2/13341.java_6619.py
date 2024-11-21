Here is the translation of the Java code into equivalent Python:

```Python
class PPC64_Elf_Relocation_Constants:
    R_PPc64_NONE = 0
    R_PPc64_ADDR32 = 1
    R_PPc64_ADDR24 = 2
    R_PPc64_ADDR16 = 3
    R_PPc64_ADDR16_LO = 4
    R_PPc64_ADDR16_HI = 5
    R_PPc64_ADDR16_HA = 6
    R_PPc64_ADDR14 = 7
    R_PPc64_ADDR14_BRTAKEN = 8
    R_PPc64_ADDR14_BRNTAKEN = 9
    R_PPc64_REL24 = 10
    R_PPc64_REL14 = 11
    R_PPc64_REL14_BRTAKEN = 12
    R_PPc64_REL14_BRNTAKEN = 13
    R_PPc64_GOT16 = 14
    R_PPc64_GOT16_LO = 15
    R_PPc64_GOT16_HI = 16
    R_PPc64_GOT16_HA = 17
    R_PPc64_COPY = 19
    R_PPc64_GLOB_DAT = 20
    R_PPc64_JMP_SLOT = 21
    R_PPc64_RELATIVE = 22
    R_PPc64_UADDR32 = 24
    R_PPc64_UADDR16 = 25
    R_PPc64_REL32 = 26
    R_PPc64_PLT32 = 27
    R_PPc64_PLTREL32 = 28
    R_PPc64_PLT16_LO = 29
    R_PPc64_PLT16_HI = 30
    R_PPc64_PLT16_HA = 31
    R_PPc64_SECTOFF = 33
    R_PPc64_SECTOFF_LO = 34
    R_PPc64_SECTOFF_HI = 35
    R_PPc64_SECTOFF_HA = 36
    R_PPc64_ADDR30 = 37
    R_PPc64_ADDR64 = 38
    R_PPc64_ADDR16_HIGHER = 39
    R_PPc64_ADDR16_HIGHERA = 40
    R_PPc64_ADDR16_HIGHEST = 41
    R_PPc64_ADDR16_HIGHESTA = 42
    R_PPc64_UADDR64 = 43
    R_PPc64_REL64 = 44
    R_PPc64_PLT64 = 45
    R_PPc64_PLTREL64 = 46
    R_PPc64_TOC16 = 47
    R_PPc64_TOC16_LO = 48
    R_PPc64_TOC16_HI = 49
    R_PPc64_TOC16_HA = 50
    R_PPc64_PLTGOT16 = 52
    R_PPc64_PLTGOT16_LO = 53
    R_PPc64_PLTGOT16_HI = 54
    R_PPc64_PLTGOT16_HA = 55
    R_PPc64_ADDR16_DS = 56
    R_PPc64_ADDR16_LO_DS = 57
    R_PPc64_GOT16_DS = 58
    R_PPc64_GOT16_LO_DS = 59
    R_PPc64_PLT16_LO_DS = 60
    R_PPc64_SECTOFF_DS = 61
    R_PPc64_SECTOFF_LO_DS = 62
    R_PPc64_TOC16_DS = 63
    R_PPc64_TOC16_LO_DS = 64
    R_PPc64_PLTGOT16_DS = 65
    R_PPc64_PLTGOT16_LO_DS = 66

    PPC64_WORD32 = 0xFFFFFFFF
    PPC64_WORD30 = 0xFFFFFFFC
    PPC64_LOW24 = 0x03FFFFFC
    PPC64_LOW14 = 0x0020FFFC
    PPC64_HALF16 = 0xFFFF

    def __init__(self):
        pass
```

Please note that Python does not support direct equivalent of Java's `public static final` variables. In this translation, I have used the same variable names as in the original code to maintain consistency and readability.