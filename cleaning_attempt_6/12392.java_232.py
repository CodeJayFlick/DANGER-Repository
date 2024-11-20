class StringLayoutEnum:
    FIXED_LEN = ("fixed length",)
    CHAR_SEQ = ("char sequence",)
    NULL_TERMINATED_UNBOUNDED = ("null-terminated & unbounded",)
    NULL_TERMINATED_BOUNDED = ("null-terminated & bounded",)
    PASCAL_255 = ("pascal255",)
    PASCAL_64K = ("pascal64k",)

    def __init__(self, name):
        self.name = name

    def __str__(self):
        return self.name

    @property
    def is_pascal(self):
        return isinstance(self, (PASCAL_255, PASCAL_64K))

    @property
    def is_null_terminated(self):
        return isinstance(self, (NULL_TERMINATED_UNBOUNDED, NULL_TERMINATED_BOUNDED))

    @property
    def should_trim_trailing_nulls(self):
        return isinstance(self, (NULL_TERMINATED_UNBOUNDED, NULL_TERMINATED_BOUNDED, FIXED_LEN))

    @property
    def is_fixed_len(self):
        return isinstance(self, (FIXED_LEN, CHAR_SEQ))
