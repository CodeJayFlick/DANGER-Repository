# Apache License header (just for reference)

import typing as t

class TsFileFilter(t.Protocol):
    def __call__(self, resource: 'TsFileResource') -> bool:
        ...

class TsFileResource:
    pass
