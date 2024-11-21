# MachConstants.py

MH_MAGIC = 0xfeedface
MH_MAGIC_64 = 0xfeedfacf
CIGAM = 0xcefaedfe
CIGAM_64 = 0xcffaedfe

def is_magic(magic):
    return magic in [MH_MAGIC, MH_MAGIC_64, CIGAM, CIGAM_64]

NAME_LENGTH = 16
DATA_TYPE_CATEGORY = "/MachO"
