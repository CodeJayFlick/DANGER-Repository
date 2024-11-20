class AbstractDBTraceSymbolSingleTypeView:
    def __init__(self, manager: 'DBTraceSymbolManager', type_id: int, store: 'DBCachedObjectStore'):
        self.manager = manager
        self.type_id = type_id
        self.store = store

        self.view = self.construct_view()
        self.symbols_by_parent_id = {k: v for k, v in self.store.as_map().items()}
        self.symbols_by_name = {k: v for k, v in self.store.as_map().items()}

    def construct_view(self):
        return frozenset(self.store.as_map().values())

    @property
    def manager(self):
        return self.manager

    # TODO: A place to store/manager/generate/whatever dynamic symbols
    # TODO: Do I generate them, or am I given them?
    def get_all(self, include_dynamic_symbols=False):
        return self.view

    def get_children_named(self, name: str, parent: 'TraceNamespaceSymbol'):
        try:
            dbns_parent = self.manager.assert_is_mine(parent)
            return frozenset(s for s in self.symbols_by_parent_id.get(dbns_parent.id) if s.name == name)
        except Exception as e:
            print(f"Error occurred while getting children named {name}: {str(e)}")

    def get_children(self, parent: 'TraceNamespaceSymbol'):
        try:
            dbns_parent = self.manager.assert_is_mine(parent)
            return frozenset(s for s in self.symbols_by_parent_id.get(dbns_parent.id))
        except Exception as e:
            print(f"Error occurred while getting children of {parent}: {str(e)}")

    def get_named(self, name: str):
        try:
            return frozenset(s for s in self.symbols_by_name.get(name))
        except Exception as e:
            print(f"Error occurred while getting named symbols with the name '{name}': {str(e)}")

    def get_with_matching_name(self, glob: str, case_sensitive=True):
        predicate = UserSearchUtils.create_search_pattern(glob, case_sensitive).as_predicate()
        return frozenset(s for s in self.view if predicate.test(s.name))

    def get_by_key(self, key: int) -> 'T':
        try:
            return self.store.get_object_at(key)
        except Exception as e:
            print(f"Error occurred while getting symbol with the key {key}: {str(e)}")

    def invalidate_cache(self):
        self.store.invalidate_cache()
