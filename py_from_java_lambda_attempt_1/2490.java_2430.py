Here is the translation of the Java code into Python:

```Python
class DBTraceSymbolMultipleTypesWithLocationView:
    def __init__(self, manager: 'DBTraceSymbolManager', parts):
        super().__init__(manager, parts)

    @staticmethod
    def get_parts(self) -> list:
        return self.parts

    def child_with_name_at(self, name: str, snap: int, thread: 'Thread', address: Address, parent: 'Namespace'):
        for p in self.get_parts():
            symbol = p.child_with_name_at(name, snap, thread, address, parent)
            if symbol:
                return symbol
        return None

    def get_at(self, snap: int, thread: 'Thread', address: Address, include_dynamic_symbols: bool) -> list:
        return [p.get_at(snap, thread, address, include_dynamic_symbols) for p in self.get_parts()]

    def get_intersecting(self, span: range, thread: 'Thread', range: tuple, include_dynamic_symbols: bool, forward: bool) -> list:
        db_thread = None if thread is None else manager.assert_is_mine(thread)
        space = manager.id_map[DBTraceSpaceKey.create(range[0], db_thread, 0), False]
        if space is None:
            return []
        
        sids = [s for s in space.reduce(TraceAddressSnapRangeQuery.intersecting(range, span).starting(forward))]
        matching_tid = [s for s in sids if DBTraceSymbolManager.unpack_type_id(s) in [p.typeID for p in self.get_parts()]]
        return [self.store.get_object_at(DBTraceSymbolManager.unpack_key(s)) for s in matching_tid]
```

Please note that Python does not support Java's `@SafeVarargs` or `@SuppressWarnings("unchecked")`, so I did not include those annotations. Also, the type of some variables (like `manager`) is inferred based on their usage and might need to be adjusted according to your actual code.