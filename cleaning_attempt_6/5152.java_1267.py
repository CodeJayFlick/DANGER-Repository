class MSProductType:
    CXX_COMPILER = ("C++ Compiler",)
    C_COMPILER = ("C Compiler",)
    ASSEMBLER = ("Assembler",)
    IMPORT_LINKER = ("Linker",)
    EXPORT_LINKER = ("Linker",)
    IMPORT_EXPORT_LINKER = ("Linker",)
    LINKER = ("Linker",)
    CVT_RES = ("CVTRes",)

    UNKNOWN = ("Unknown",)

    def __init__(self, desc):
        self.desc = desc

    def __str__(self):
        return self.desc
