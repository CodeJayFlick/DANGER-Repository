class X86_64MachoRelocationConstants:
    """X86_64 Mach-O relocation constants"""

    # For absolute addresses
    UNSIGNED = 0

    # For signed 32-bit displacement
    SIGNED = 1

    # A CALL/JMP instruction with 32-bit displacement
    BRANCH = 2

    # A MOVQ load of a GOT entry
    GOT_LOAD = 3

    # Other GOT references
    GOT = 4

    # Must be followed by a X86_64_RELOC_UNSIGNED
    SUBTRACTOR = 5

    # For signed 32-bit displacement with a -1 addend
    SIGNED_1 = 6

    # For signed 32-bit displacement with a -2 addend
    SIGNED_2 = 7

    # For signed 32-bit displacement with a -4 addend
    SIGNED_4 = 8

    # For thread local variables
    TLV = 9
