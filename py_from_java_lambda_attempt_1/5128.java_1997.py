Here is the translation of the Java code into Python:

```Python
class MachineConstants:
    UNKNOWN = 0x0000
    I386 = 0x014c
    R3000 = 0x0162
    R4000 = 0x0166
    R10000 = 0x0168
    WCEMIPSV2 = 0x0169
    ALPHA = 0x0184
    SH3 = 0x01a2
    SH3DSP = 0x01a3
    SH3E = 0x01a4
    SH4 = 0x01a6
    SH5 = 0x01a8
    ARM = 0x01c0
    THUMB = 0x01c2
    ARMNT = 0x01c4
    AM33 = 0x01d3
    POWERPC = 0x01F0
    POWERPCFP = 0x01f1
    IA64 = 0x0200
    MIPS16 = 0x0266
    ALPHA64 = 0x0284
    MIPSFPU = 0x0366
    MIPSFPU16 = 0x0466
    TRICORE = 0x0520
    CEF = 0x0CEF
    EBC = 0x0EBC

    AMD64 = 0x8664
    M32R = 0x9041
    ARM64 = 0xaa64
    CEE = 0xC0EE

    AXP64 = ALPHA64
```

Note that Python does not have a direct equivalent to Java's `public final static` keywords. The class itself is public, and the constants are simply defined at the top level of the module.