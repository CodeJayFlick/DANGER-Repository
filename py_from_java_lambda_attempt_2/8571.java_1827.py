Here is the translation of the Java code to Python:
```python
class PeCoffSectionSymbolApplier:
    def __init__(self, applicator: 'PdbApplicator', iter):
        super().__init__(applicator, iter)
        abstract_symbol = next(iter)
        if not isinstance(abstract_symbol, PeCoffSectionMsSymbol):
            raise AssertionError(f"Invalid symbol type: {type(abstract_symbol).__name__}")
        self.symbol = abstract_symbol

    def apply(self) -> None:
        section_num = self.symbol.get_section_number()
        real_address = self.symbol.get_rva()
        length = self.symbol.get_length()
        characteristics = self.symbol.get_characteristics()
        align = self.symbol.get_align()
        name = self.symbol.get_name()

        applicator.put_real_addresses_by_section(section_num, real_address)
        applicator.add_memory_section_refinement(self.symbol)

    def apply_to(self, applier: 'MsSymbolApplier') -> None:
        pass
```
Note that I used the `super().__init__` syntax to call the parent class's constructor. In Python, this is equivalent to calling the superclass's constructor using `PdbApplicator.__init__(self, applicator, iter)`.