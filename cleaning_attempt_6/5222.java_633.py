class XCoffSymbolStorageClassCSECT:
    # csect storage class, in x_smlas.
    XMC_PR = 0          # program code
    XMC_RO = 1           # read only constant
    XMC_DB = 2           # debug dictionary table
    XMC_TC = 3           # general TOC entry
    XMC_UA = 4           # unclassified
    XMC_RW = 5           # read/write data
    XMC_GL = 6           # global linkage
    XMC_XO = 7           # extended operation
    XMC_SV = 8           # 32-bit supervisor call descriptor csect
    XMC_BS = 9           # BSS class (uninitialized static internal)
    XMC_DS = 10          # csect containing a function descriptor
    XMC_UC = 11          # unnamed FORTRAN common
    XMC_TI = 12          # reserved
    XMC_TB = 13          # reserved
    XMC_TC0 = 15         # TOC anchor for TOC addressability
    XMC_TD = 16          # scalar data entry in TOC
    XMC_SV64 = 17        # 64-bit supervisor call descriptor csect
    XMC_SV3264 = 18      # supervisor call descriptor csect for both 32- and 64-bit

XCoffSymbolStorageClassCSECT = XCoffSymbolStorageClassCSECT()
