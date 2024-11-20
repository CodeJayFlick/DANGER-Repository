class DebugHostSymbol2:
    def enumerate_children_ex(self, kind: int, name: str, search_info) -> 'DebugHostSymbolEnumerator':
        pass  # implement this method in your subclass

    def get_language(self) -> int:
        pass  # implement this method in your subclass


class DebugHostSymbolEnumerator:
    pass
