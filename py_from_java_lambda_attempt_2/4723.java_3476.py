Here is the equivalent Python code:

```Python
class ElfProgramHeaderConstants:
    def __init__(self):
        pass

    # Segment Types
    PT_NULL = 0
    PT_LOAD = 1
    PT_DYNAMIC = 2
    PT_INTERP = 3
    PT_NOTE = 4
    PT_SHLIB = 5
    PT_PHDR = 6
    PT_TLS = 7

    PT_GNU_EH_FRAME = 0x6474e550
    PT_GNU_STACK = 0x6474e551
    PT_GNU_RELRO = 0x6474e552
    PT_SUNWBSS = 0x6ffffffa
    PT_SUNWSTACK = 0x6ffffffb

    # Segment Flags
    PF_X = 1 << 0
    PF_W = 1 << 1
    PF_R = 1 << 2
    PF_MASKOS = 0x0ff00000
    PF_MASKPROC = 0xf0000000


# Example usage:
elf_constants = ElfProgramHeaderConstants()
print(elf_constants.PT_NULL)  # Output: 0
```

Note that Python does not have a direct equivalent to Java's `public static final` keywords. In Python, you can simply define the constants as class attributes or variables at the top level of your module.