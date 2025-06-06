Here is the equivalent Python code:

```Python
class DwarfSourceLanguage:
    DW_LANG_C89 = 1
    DW_LANG_C = 2
    DW_LANG_Ada83 = 3
    DW_LANG_CPP = 4
    DW_LANG_COBOL74 = 5
    DW_LANG_COBOL85 = 6
    DW_LANG_Fortran77 = 7
    DW_LANG_Fortran90 = 8
    DW_LANG_Pascal83 = 9
    DW_LANG_Modula2 = 0xa
    DW_LANG_Java = 0xb
    DW_LANG_C99 = 0xc
    DW_LANG_Ada95 = 0xd
    DW_LANG_Fortran95 = 0xe
    DW_LANG_PL1 = 0xf
    DW_LANG_ObjC = 10
    DW_LANG_ObjC_PP = 11
    DW_LANG_UPC = 12
    DW_LANG_D = 13
    DW_LANG_Python = 14
    DW_LANG_OpenCL = 15
    DW_LANG_Go = 16
    DW_LANG_Modula3 = 17
    DW_LANG_Haskell = 18
    DW_LANG_CPP03 = 19
    DW_LANG_CPP11 = 0x1a
    DW_LANG_OCaml = 0x1b
    DW_LANG_Rust = 0x1c
    DW_LANG_C11 = 0x1d
    DW_LANG_Swift = 0x1e
    DW_LANG_Julia = 0x1f
    DW_LANG_Dylan = 20
    DW_LANG_CPP14 = 21
    DW_LANG_Fortran03 = 22
    DW_LANG_Fortran08 = 23
    DW_LANG_RenderScript = 24
    DW_LANG_BLISS = 25

    lo_user = 0x8000
    hi_user = 0xffff

    Mips_Assembler = 0x8001
    GOOGLE_RenderScript = 0x8e57
    SUN_Assembler = 0x9001
    ALTIUM_Assembler = 0x9101
    Borland_Delphi = 0xb000
```

Note that Python does not support the concept of "public" or "final", so I removed those. Also, in Python, class variables are defined without `static`, and they do not need to be declared before use.