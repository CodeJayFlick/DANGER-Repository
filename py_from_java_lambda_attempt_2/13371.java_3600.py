Here is the translation of the Java code to Python:

```Python
class Sparc_Elf_Relocation_Constants:
    R_SPARC_NONE = 0  # No calculation
    R_SPARC_5 = 44  # S + A
    R_SPARC_6 = 45  # S + A
    R_SPARC_7 = 43  # S + A
    R_SPARC_8 = 1  # S + A
    R_SPARC_10 = 30  # S + A
    R_SPARC_11 = 31  # S + A
    R_SPARC_13 = 11  # S + A
    R_SPARC_16 = 2  # S + A
    R_SPARC_22 = 10  # S + A
    R_SPARC_LO10 = 12  # (S + A) & 0x3FF
    R_SPARC_HI22 = 9  # (S + A) >> 10
    R_SPARC_DISP8 = 4  # S + A - P
    R_SPARC_DISP16 = 5  # S + A - P
    R_SPARC DISP32 = 6  # S + A - P
    R_SPARC_WDISP16 = 40  # (S + A - P) >> 2
    R_SPARC_WDISP19 = 41  # (S + A - P) >> 2
    R_SPARC_WDISP22 = 8  # (S + A - P) >> 2
    R_SPARC_WDISP30 = 7  # (S + A - P) >> 2
    R_SPARC_PC10 = 16  # (S + A - P) & 0x3FF
    R_SPARC_PC22 = 17  # (S + A - P) >> 10
    R_SPARC_PLT32 = 24  # L + A
    R_SPARC_PCPLT10 = 29  # (L + A - P) & 0x3FF
    R_SPARC_PCPLT22 = 28  # (L + A - P) >> 10
    R_SPARC_PCPLT32 = 27  # L + A - P
    R_SPARC_GOT10 = 13  # G & 0x3FF
    R_SPARC_GOT13 = 14  # G
    R_SPARC_GOT22 = 15  # G >> 10
    R_SPARC_WPLT30 = 18  # (L + A - P) >> 2
    R_SPARC_LOPLT10 = 26  # (L + A) & 0x3FF
    R_SPARC_HIPLT22 = 25  # (L + A) >> 10

    R_SPARC_JMP_SLOT = 21
    R_SPARC_UA32 = 23  # S + A
    R_SPARC_GLOB_DAT = 20  # S + A
    R_SPARC_RELATIVE = 22  # B + A
    R_SPARC_COPY = 19  # No calculation

    def __init__(self):
        pass


# Create an instance of the class to use its constants.
sparc_constants = Sparc_Elf_Relocation_Constants()
```