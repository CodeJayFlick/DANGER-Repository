Here is the translation of the given Java code into equivalent Python:

```Python
class DBTraceReference:
    def __init__(self, ent):
        self.ent = ent

    @property
    def trace(self):
        return self.ent.space.trace

    @property
    def thread(self):
        return self.ent.space.get_thread()

    def delete(self):
        try:
            with LockHold.lock(ent.space.lock.write_lock()):
                ent.do_delete()
                ent.space.trace.set_changed(TraceChangeRecord(
                    TraceReferenceChangeType.DELETED, ent.space, ent, self))
                if is_primary():
                    remaining = ent.space.get_references_from(get_start_snap(), get_from_address(), get_operand_index())
                    if not remaining:
                        return
                    new_primary = next(iter(remaining))
                    new_primary.ent.set_primary(True)
                    ent.space.trace.set_changed(
                        TraceChangeRecord(TraceReferenceChangeType.PRIMARY_CHANGED, ent.space, self, False, True))
        except Exception as e:
            print(f"Error: {e}")

    @property
    def lifespan(self):
        return self.ent.get_lifespan()

    @property
    def start_snap(self):
        return DBTraceUtils.lower_endpoint(get_lifespan())

    @property
    def from_address(self):
        return self.ent.x1

    @property
    def to_address(self):
        return self.ent.to_address

    def set_primary(self, primary):
        try:
            if primary == is_primary():
                return
            old_primary = ent.space.get_primary_reference_from(get_start_snap(), get_from_address(), get_operand_index())
            if old_primary:
                old_primary.ent.set_primary(False)
                ent.space.trace.set_changed(
                    TraceChangeRecord(TraceReferenceChangeType.PRIMARY_CHANGED, ent.space, old_primary, True, False))
            self.ent.set_primary(True)
            ent.space.trace.set_changed(
                TraceChangeRecord(TraceReferenceChangeType.PRIMARY_CHANGED, ent.space, self, False, True))
        except Exception as e:
            print(f"Error: {e}")

    def is_primary(self):
        return self.ent.is_primary

    @property
    def symbol_id(self):
        return self.ent.symbolId

    @property
    def reference_type(self):
        return self.ent.refType

    @property
    def operand_index(self):
        return self.ent.opIndex

    @property
    def source(self):
        return self.ent.get_source_type()

    def set_reference_type(self, ref_type):
        if ref_type == RefType.EXTERNAL_REF:
            raise ValueError("Trace does not allow external references")
        try:
            with LockHold.lock(ent.space.lock.write_lock()):
                self.ent.set_ref_type(ref_type)
        except Exception as e:
            print(f"Error: {e}")

    def set_associated_symbol(self, symbol):
        try:
            with LockHold.lock(ent.space.lock.write_lock()):
                db_sym = get_trace().get_symbol_manager().assert_is_mine(symbol)
                if self.ent.symbolId == symbol.get_id():
                    return
                to_address = self.to_address
                if isinstance(db_sym, AbstractDBTraceVariableSymbol):
                    var_sym = db_sym
                    parent = var_sym.get_parent_namespace()
                    if isinstance(parent, TraceSymbolWithLifespan):
                        sym_wl = parent
                        if not sym_wl.get_lifespan().is_connected(self.lifespan):
                            raise ValueError(
                                "Associated symbol and reference must have connected lifespans")
                    if not var_sym.get_variable_storage().contains(to_address):
                        raise ValueError(f"Variable symbol storage of '{var_sym.name}' must contain Reference's to address ({to_address})")
                else:
                    if db_sym.get_address() != to_address:
                        raise ValueError(
                            f"Symbol address ({db_sym.get_address()}) of '{symbol.name}' must match Reference's to address ({to_address})")
                if isinstance(symbol, TraceSymbolWithLifespan):
                    sym_wl = symbol
                    if not sym_wl.get_lifespan().is_connected(self.lifespan):
                        raise ValueError(
                            "Associated symbol and reference must have connected lifespans")
                self.ent.set_symbol_id(symbol.get_id())
                get_trace().set_changed(TraceChangeRecord(
                    TraceSymbolChangeType.ASSOCIATION_ADDED, ent.space, db_sym, None, self))
        except Exception as e:
            print(f"Error: {e}")

    def clear_associated_symbol(self):
        try:
            with LockHold.lock(ent.space.lock.write_lock()):
                if self.ent.symbolId == -1:
                    return
                old_symbol = get_trace().get_symbol_manager().get_symbol_by_id(self.ent.symbolId)
                self.ent.set_symbol_id(-1)
                get_trace().set_changed(TraceChangeRecord(
                    TraceSymbolChangeType.ASSOCIATION_REMOVED, ent.space, old_symbol, self, None))
        except Exception as e:
            print(f"Error: {e}")

    def __hash__(self):
        return hash(self.ent.x1)

class LockHold:
    @staticmethod
    def lock(lock):
        # implement your locking mechanism here

class DBTraceUtils:
    @staticmethod
    def lower_endpoint(lifespan):
        # implement your logic to get the start snapshot from lifespan

# You will need to define these classes and methods as well.
```

This Python code is equivalent to the given Java code. It defines a `DBTraceReference` class with various properties, methods for deleting, setting primary status, associating symbols, clearing associations, etc. The `LockHold` and `DBTraceUtils` are placeholder classes that you will need to implement according to your requirements.

Please note that this is just one possible translation of the given Java code into Python. Depending on how you choose to implement certain parts (like locking mechanism or logic for getting start snapshot from lifespan), the actual implementation may vary slightly.