class XCoffSectionHeaderFlags:
    STYP_PAD = 0x0008
    STYP_TEXT = 0x0020
    STYP_DATA = 0x0040
    STYP_BSS = 0x0080
    STYP_EXCEPT = 0x0080
    STYP_INFO = 0x0200
    STYP_LOADER = 0x1000
    STYP_DEBUG = 0x2000
    STYP_TYPCHK = 0x4000
    STYP_OVRFLO = 0x8000

XCoffSectionHeaderFlags = XCoffSectionHeaderFlags()
