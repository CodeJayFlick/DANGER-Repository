class CoffFileHeaderFlag:
    RELFLG = 1
    EXEC = 2
    LNNO = 4
    LSYMS = 8
    MINMAL = 16
    UPDATE = 32
    SWABD = 64
    AR16WR = 128
    AR32WR = 256
    AR32W = 512
    PATCH = 1024
    NODF = 1024

# You can access the values like this:
print(CoffFileHeaderFlag.RELFLG)
