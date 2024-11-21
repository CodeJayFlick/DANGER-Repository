class ContextOp:
    def __init__(self):
        self.patexp = None  # Left-Hand side of context expression
        self.num = None     # index of word containing context var
        self.mask = None    # mask of variables bits within word
        self.shift = None   # number of bits to shift value in place

    def apply(self, walker, debug):
        val = int(self.patexp.get_value(walker))
        val <<= self.shift
        walker.parser_context.set_context_word(self.num, val, self.mask)
        if debug:
            debug.dump_context_set(walker.parser_context, self.num, val, self.mask)

    @staticmethod
    def restore_xml(parser):
        el = parser.start("context_op")
        ContextOp.__dict__.update({
            "num": int(el.get_attribute("i")),
            "shift": int(el.get_attribute("shift")),
            "mask": int(el.get_attribute("mask"))
        })
        self.patexp = PatternExpression.restore_expression(parser)
        parser.end(el)

    @property
    def pattern_expression(self):
        return self.patexp

    @property
    def word_index(self):
        return self.num

    @property
    def mask_value(self):
        return self.mask

    @property
    def shift_value(self):
        return self.shift

    def __str__(self):
        sb = "ctx&"
        for _ in range(self.num):
            sb += "SS:SS:SS:SS:"
        sb += f"{NumericUtilities.convert_mask_to_hex_string(self.mask, 8, False, 2, ":")} := "
        sb += str(self.patexp)
        sb += f" (<< {self.shift})"
        return sb
