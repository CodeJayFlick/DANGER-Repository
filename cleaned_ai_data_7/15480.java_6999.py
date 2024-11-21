import re

class HyphenNormalizer:
    SOFT_HYPHEN = 0x00AD
    HYPHENS = {0x002D, 0x007E, 0x00AD, 0x058A, 0x05BE, 0x2010, 0x2011, 0x2012, 0x2013,
               0x2014, 0x2015, 0x2053, 0x207B, 0x208B, 0x2212, 0x2E3A, 0x2E3B, 0x301C,
               0x3030, 0xFE31, 0xFE32, 0xFE58, 0xFE63, 0xFF0D}

    def is_hyphen_like(code_point):
        return code_point in HYPHENS

    @staticmethod
    def normalize_hyphens(s):
        temp = ''
        for cp in s:
            if cp == SOFT_HYPHEN:  # drop soft hyphens
                continue
            elif HyphenNormalizer.is_hyphen_like(ord(cp)):
                temp += '-'
            else:
                temp += cp
        return temp

    def preprocess(self, tokens):
        return [self.normalize_hyphens(token) for token in tokens]
