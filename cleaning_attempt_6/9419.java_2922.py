class ManagedMenuItem:
    def get_group(self):
        pass  # Implement this method in your subclass

    def get_subgroup(self):
        pass  # Implement this method in your subclass

    def get_menu_item_text(self):
        pass  # Implement this method in your subclass

    @property
    def menu_item(self):
        pass  # Implement this method in your subclass (returns a JMenuItem or Menu)

    def dispose(self):
        pass  # Implement this method to release resources used by the object

    def remove_action(self, action: 'DockingActionIf') -> bool:
        return False  # Default implementation; implement this method in your subclass if needed

    def is_empty(self) -> bool:
        return True  # Default implementation; implement this method in your subclass if needed
