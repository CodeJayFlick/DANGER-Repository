class TokenPattern:
    def __init__(self, location):
        self.location = location
        self.pattern = InstructionPattern(True)
        self.toklist = VectorSTL()
        self.left_ellipsis = False
        self.right_ellipsis = False

    @property
    def get_left_ellipses(self):
        return self.left_ellipsis

    @get_left_ellipses.setter
    def set_left_ellipsis(self, val):
        self.left_ellipsis = val

    @property
    def get_right_ellipses(self):
        return self.right_ellipsis

    @get_right_ellipses.setter
    def set_right_ellipsis(self, val):
        self.right_ellipsis = val

    def dispose(self):
        pass  # No equivalent in Python

    def resolve_tokens(self, tok1, tok2):
        calls += 1
        reversedirection = False
        minsize = len(tok1.toklist) if len(tok1.toklist) < len(tok2.toklist) else len(tok2.toklist)
        for i in range(minsize):
            if not (tok1.toklist[i].equals(tok2.toklist[i])):
                raise SleighError("Mismatched tokens when combining patterns", self.location)

    def build_single(self, startbit, endbit, byteval):
        offset = 0
        size = endbit - startbit + 1
        while startbit >= 8:
            offset += 1
            startbit -= 8
            endbit -= 8

        mask = -(2 ** (32 - size))
        byteval >>= (32 - size)
        return PatternBlock(offset, mask, byteval)

    def build_big_block(self, size, bitstart, bitend, value):
        block = None
        startbit = (size * 8) - 1 - bitend
        endbit = (size * 8) - 1 - bitstart

        if self.isBigEndian():
            block = self.build_single(startbit, endbit, int(value))
        else:
            block = self.build_single(endbit + (7 - bitend), endbit, int(value))

    def build_little_block(self, size, bitstart, bitend, value):
        startbit, endbit = 0, 0
        if not self.isBigEndian():
            startbit = (size * 8) - 1 - bitend
            endbit = (size * 8) - 1 - bitstart

    def __init__(self, location, tok):
        super().__init__(location)
        self.toklist.push_back(tok)

    @property
    def get_pattern(self):
        return self.pattern

    def simplify_pattern(self, tokpat):
        pass  # No equivalent in Python

    def do_and(self, tokpat):
        res = TokenPattern(self.location, None)
        sa = res.resolve_tokens(self, tokpat)
        res.pattern = self.pattern.doAnd(tokpat.pattern, sa)

    def do_or(self, tokpat):
        res = TokenPattern(self.location, None)
        sa = res.resolve_tokens(self, tokpat)
        res.pattern = self.pattern.doOr(tokpat.pattern, sa)

    def do_cat(self, tokpat):
        pass  # No equivalent in Python

class VectorSTL:
    def __init__(self):
        pass  # No equivalent in Python

    def push_back(self, val):
        pass  # No equivalent in Python

    def copy(self):
        return self.__class__()

class InstructionPattern:
    def __init__(self, tf):
        pass  # No equivalent in Python

    @property
    def get_pattern(self):
        return self.pattern

    def doAnd(self, pat1, sa):
        pass  # No equivalent in Python

    def doOr(self, pat2, sa):
        pass  # No equivalent in Python

class PatternBlock:
    def __init__(self, offset, mask, byteval):
        pass  # No equivalent in Python
