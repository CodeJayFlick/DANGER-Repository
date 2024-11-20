Here is the translation of the given Java code into Python:

```Python
class LabelFieldSearcher:
    def __init__(self, program: 'ghidra.program.model.Program', start_loc: 'ghidra.program.model.location.ProgramLocation',
                 set_view: 'ghidra.program.model.address.AddressSetView' = None,
                 forward: bool = True, pattern: str = '') -> None:
        self.program = program
        self.symbol_table = program.get_symbol_table()
        if set_view is not None:
            symbol_iterator = self.program.get_symbol_table().get_primary_symbols(set_view, forward)
            ref_iterator = self.program.get_reference_manager().get_reference_destinations(set_view, forward)
        else:
            symbol_iterator = self.program.get_symbol_table().get_primary_symbols(start_loc.get_address(), forward)
            ref_iterator = self.program.get_reference_manager().get_reference_destinations(start_loc.get_address(), forward)

        self.iterator = SymbolAddressIterator(symbol_iterator, ref_iterator, forward)


    def advance(self) -> 'ghidra.program.model.address.Address':
        next_address = self.iterator.next()
        if next_address is None:
            return None
        self.find_matches_for_current_address(next_address)
        return next_address


    def find_matches_for_current_address(self, address: 'ghidra.program.model.address.Address') -> None:
        symbols = self.symbol_table.get_symbols(address)
        make_primary_last_item(symbols)
        for symbol in symbols:
            matcher = re.compile(symbol.name).matcher()
            while matcher.find():
                char_offset = matcher.start()
                yield LabelFieldLocation(symbol, 0, char_offset)


    def make_primary_last_item(self, symbols: list) -> None:
        i = len(symbols) - 1
        while i > 0 and not symbols[i].is_primary():
            i -= 1

        if i < len(symbols):
            primary_symbol = symbols.pop(i)
            symbols.append(primary_symbol)


class SymbolAddressIterator:
    def __init__(self, symbol_iterator: 'ghidra.program.model.symbol.SymbolIterator',
                 ref_iterator: 'ghidra.program.model.address.AddressIterator', forward: bool) -> None:
        self.symbol_iterator = symbol_iterator
        self.ref_iterator = ref_iterator
        self.forward = forward

        self.next_symbol_address = next(self.symbol_iterator, None)
        self.next_ref_address = next((ref for ref in self.ref_iterator if ref is not None), None)


    def remove(self) -> None:
        raise NotImplementedError


    @property
    def has_next(self) -> bool:
        return (self.next_symbol_address is not None or 
                self.next_ref_address is not None)

    def next(self) -> 'ghidra.program.model.address.Address':
        if self.has_next:
            address = self.next_symbol_address
            self.next_symbol_address = None

            if address is None and self.next_ref_address is not None:
                return self.next_ref_address
            else:
                return address


    def __iter__(self) -> 'SymbolAddressIterator':
        return self
```

Note: The above Python code assumes that you have the following classes:

- `ghidra.program.model.Program`
- `ghidra.program.model.location.ProgramLocation`
- `ghidra.program.model.address.AddressSetView`
- `ghidra.program.model.symbol.SymbolIterator`
- `ghidra.program.model.address.AddressIterator`

These are not standard Python libraries, so you would need to have them available in your environment.