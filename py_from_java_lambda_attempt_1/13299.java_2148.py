Here is the translation of the given Java code into equivalent Python:

```Python
class MIPS_Elf_Relocation_Constants:
    R_MIPS_NONE = 0
    R_MIPS_16 = 1
    R_MIPS_32 = 2
    R_MIPS_REL32 = 3
    R_MIPS_26 = 4
    R_MIPS_HI16 = 5
    R_MIPS_LO16 = 6
    R_MIPS_GPREL16 = 7
    R_MIPS_LITERAL = 8
    R_MIPS_GOT16 = 9
    R_MIPS_PC16 = 10
    R_MIPS_CALL16 = 11
    R_MIPS_GPREL32 = 12

    # The remaining relocs are defined on Irix, although they are not in the MIPS ELF ABI.
    R_MIPS_UNUSED1 = 13
    R_MIPS_UNUSED2 = 14
    R_MIPS_UNUSED3 = 15
    R_MIPS_SHIFT5 = 16
    R_MIPS_SHIFT6 = 17
    R_MIPS_64 = 18
    R_MIPS_GOT_DISP = 19
    R_MIPS_GOT_PAGE = 20
    R_MIPS_GOT_OFST = 21
    R_MIPS_GOT_HI16 = 22
    R_MIPS_GOT_LO16 = 23
    R_MIPS_SUB = 24
    R_MIPS_INSERT_A = 25
    R_MIPS_INSERT_B = 26
    R_MIPS_DELETE = 27
    R_MIPS_HIGHER = 28
    R_MIPS_HIGHEST = 29
    R_MIPS_CALL_HI16 = 30
    R_MIPS_CALL_LO16 = 31
    R_MIPS_SCN_DISP = 32
    R_MIPS_REL16 = 33
    R_MIPS_ADD_IMMEDIATE = 34
    R_MIPS_PJUMP = 35
    R_MIPS_RELGOT = 36
    R_MIPS_JALR = 37

    # TLS relocations.
    R_MIPS_TLS_DTPMOD32 = 38
    R_MIPS_TLS_DTPREL32 = 39
    R_MIPS_TLS_DTPMOD64 = 40
    R_MIPS_TLS_DTPREL64 = 41
    R_MIPS_TLS_GD = 42
    R_MIPS_TLS_LDM = 43
    R_MIPS_TLS_DTPREL_HI16 = 44
    R_MIPS_TLS_DTPREL_LO16 = 45
    R_MIPS_TLS_GOTTPREL = 46
    R_MIPS_TLS_TPREL32 = 47
    R_MIPS_TLS_TPREL64 = 48
    R_MIPS_TLS_TPREL_HI16 = 49
    R_MIPS_TLS_TPREL_LO16 = 50

    # These relocs are used for the mips16.
    R_MIPS16_26 = 100
    R_MIPS16_GPREL = 101
    R_MIPS16_GOT16 = 102
    R_MIPS16_CALL16 = 103
    R_MIPS16_HI16 = 104
    R_MIPS16_LO16 = 105
    R_MIPS16_TLS_GD = 106
    R_MIPS16_TLS_LDM = 107
    R_MIPS16_TLS_DTPREL_HI16 = 108
    R_MIPS16_TLS_DTPREL_LO16 = 109
    R_MIPS16_TLS_GOTTPREL = 110

    # These relocations are specific to VxWorks.
    R_MIPS_COPY = 126
    R_MIPS_JUMP_SLOT = 127

    # These relocations are specific to the MicroMIPS.
    R_MICROMIPS_26_S1 = 133
    R_MICROMIPS_HI16 = 134
    R_MICROMIPS_LO16 = 135
    R_MICROMIPS_GPREL16 = 136
    R_MICROMIPS_LITERAL = 137
    R_MICROMIPS_GOT16 = 138
    R_MICROMIPS_PC7_S1 = 139
    R_MICROMIPS_PC10_S1 = 140

    # Masks for manipulating MIPS relocation targets.
    MIPS_LOW26 = 0x03FFFFFF


# Private constructor to prevent instantiation of this class.
def __init__(self):
    pass