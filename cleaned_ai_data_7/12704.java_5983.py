class SymbolTableListener:
    def symbol_added(self, symbol):
        """Notification that a new symbol has been added."""
        pass  # Implement this method in your subclass.

    def symbol_removed(self, addr: int, name: str, is_local: bool) -> None:
        """Notification that a symbol was removed."""
        pass  # Implement this method in your subclass.

    def symbol_renamed(self, symbol, old_name):
        """Notification that the given symbol has been renamed."""
        pass  # Implement this method in your subclass.

    def primary_symbol_set(self, symbol) -> None:
        """Notification that a new primary symbol was set."""
        pass  # Implement this method in your subclass.

    def symbol_scope_changed(self, symbol):
        """Notification that the scope of a symbol has changed."""
        pass  # Implement this method in your subclass.

    def external_entry_point_added(self, addr: int) -> None:
        """Notification that an external entry point was added at the given address."""
        pass  # Implement this method in your subclass.

    def external_entry_point_removed(self, addr: int) -> None:
        """Notification that an external entry point was removed from the given address."""
        pass  # Implement this method in your subclass.

    def association_added(self, symbol, ref):
        """Notification that a new reference-symbol association has been added."""
        pass  # Implement this method in your subclass.

    def association_removed(self, ref) -> None:
        """Notification that the association between a reference and any symbol was removed."""
        pass  # Implement this method in your subclass.
