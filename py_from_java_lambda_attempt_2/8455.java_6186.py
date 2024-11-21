Here is the translation of the given Java code into equivalent Python:

```Python
class MethodListMsType:
    PDB_ID = 0x1206

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader)

    @property
    def pdb_id(self) -> int:
        return self.PDB_ID

    def parse_one_record(self, pdb_in: 'AbstractPdb', reader: 'PdbByteReader') -> 'MethodRecordMs':
        return MethodRecordMs(pdb_in, reader)


class AbstractPdb:
    pass


class PdbByteReader:
    pass


class MethodRecordMs:
    def __init__(self, pdb_in: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        self.pdb_in = pdb_in
        self.reader = reader

```

Please note that Python does not have direct equivalent of Java's `public`, `private` and other access modifiers. In Python, everything is public by default unless you use double underscore (`__`) to make it private.

Also, the translation assumes that there are classes `AbstractPdb`, `PdbByteReader`, and `MethodRecordMs`. These classes were not provided in the original Java code so I just left them as placeholders.