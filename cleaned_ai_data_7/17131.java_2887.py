import re

class IndexUtils:
    @staticmethod
    def remove_quotation(v):
        if v.startswith("'") or v.startswith('"'):
            start = 1
        else:
            start = 0
        if v.endswith("'") or v.endswith('"'):
            end = len(v) - 1
        else:
            end = len(v)
        return v[start:end]

IndexUtils()
