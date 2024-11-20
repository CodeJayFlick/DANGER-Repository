Here is the translation of the Java code into Python:

```Python
class X86_64_Elf_Relocation_Constants:
    R_X86_64_NONE = 0  # No reloc
    R_X86_64_64 = 1     # Direct 64 bit
    R_X86_64_PC32 = 2   # PC relative 32 bit signed
    R_X86_64_GOT32 = 3  # 32 bit GOT entry
    R_X86_64_PLT32 = 4  # 32 bit PLT address
    R_X86_64_COPY = 5   # Copy symbol at runtime
    R_X86_64_GLOB_DAT = 6  # Create GOT entry
    R_X86_64_JUMP_SLOT = 7  # Create PLT entry
    R_X86_64_RELATIVE = 8  # Adjust by program base
    R_X86_64_GOTPCREL = 9   # 32 bit signed pc relative offset to GOT
    R_X86_64_32 = 10      # Direct 32 bit zero extended
    R_X86_64_32S = 11     # Direct 32 bit sign extended
    R_X86_64_16 = 12      # Direct 16 bit zero extended
    R_X86_64_PC16 = 13   # 16 bit sign extended pc relative
    R_X86_64_8 = 14       # Direct 8 bit sign extended
    R_X86_64_PC8 = 15     # 8 bit sign extended pc relative

    R_X86_64_DTPMOD64 = 16  # ID of module containing symbol
    R_X86_64_DTPOFF64 = 17   # Offset in module's TLS block 
    R_X86_64_TPOFF64 = 18     # offset in the initial TLS block

    R_X86_64_TLSGD = 19      # 32 bit signed PC relative offset to two GOT entries for GD symbol
    R_X86_64_TLSLD = 20       # 32 bit signed PC relative offset to two GOT entries for LD symbol 
    R_X86_64_DTPOFF32 = 21     # Offset in TLS block

    R_X86_64_GOTTPOFF = 22   # 32 bit signed pc relative offst to GOT entry for IE symbol
    R_X86_64_TPOFF32 = 23      # offset in initial TLS block

    R_X86_64_PC64 = 24       # PC relative 64 bit

    R_X86_64_GOTOFF64 = 25     # 64 bit offset to GOT
    R_X86_64_GOTPC32 = 26   # 32 bit signed pc relative offset to GOT
    R_X86_64_GOT64 = 27      # 64 bit GOT entry offset

    R_X86_64_GOTPCREL64 = 28     # 64 bit pc relative offset to GOT entry
    R_X86_64_GOTPC64 = 29       # 64 bit pc relative offset to GOT
    R_X86_64_GOTPLT64 = 30      #
    R_X86_64_PLTOFF64 = 31     # 64 bit GOT relative offset to PLT entry

    R_X86_64_SIZE32 = 32        # Size of symbol plus 32 bit addend
    R_X86_64_SIZE64 = 33         # Size of symbol plus 64 bit addend

    R_X86_64_GOTPC32_TLSDESC = 34     #
    R_X86_64_TLSDESC_CALL = 35      # Marker for call through TLS descriptor
    R_X86_64_TLSDESC = 36          # TLS descriptor; word64   * 2
    R_X86_64_IRELATIVE = 37         # Adjust indirectly by program base

    R_X86_64_RELATIVE64 = 38        #

    R_X86_64_PC32_BND = 39      #
    R_X86_64_PLT32_BND = 40       #
    R_X86_64_GOTPCRELX = 41     # G + GOT + A - P
    R_X86_64_REX_GOTPCRELX = 42   #G + GOT + A - P

    R_X86_64_NUM = 43         #

    R_X86_64_GNU_VTINHERIT = 250 #
    R_X86_64_GNU_VTENTRY = 251  #

    def __init__(self):
        pass
```

Please note that Python does not support exactly the same syntax as Java. For example, there is no direct equivalent of `public static final` in Python.