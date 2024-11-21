class RelocationTable:
    RELOCATABLE_PROP_NAME = "Relocatable"

    def __init__(self):
        self.relocations = []

    def add(self, addr: int, type: int, values: list, bytes: bytes, symbol_name=None) -> 'Relocation':
        relocation = {'address': addr, 'type': type, 'values': values, 'bytes': bytes, 'symbol_name': symbol_name}
        self.relocations.append(relocation)
        return relocation

    def remove(self, reloc):
        if reloc in self.relocations:
            self.relocations.remove(reloc)

    def get_relocation(self, addr: int) -> dict or None:
        for relocation in self.relocations:
            if relocation['address'] == addr:
                return relocation
        return None

    def get_relations(self) -> list:
        return sorted(self.relations, key=lambda x: x['address'])

    def get_relocations(self, set):
        relocs = [reloc for reloc in self.relocations if reloc['address'] in set]
        return relocs

    def get_relocation_after(self, addr: int) -> dict or None:
        for relocation in sorted(self.relations, key=lambda x: x['address']):
            if relocation['address'] > addr:
                return relocation
        return None

    def __len__(self):
        return len(self.relocations)

    def is_relocatable(self) -> bool:
        return self.RELOCATABLE_PROP_NAME in [relocation['symbol_name'] for relocation in self.relations]
