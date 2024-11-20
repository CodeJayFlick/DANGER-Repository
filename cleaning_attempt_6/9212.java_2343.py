from abc import ABC, abstractmethod


class FieldKeyInteriorNode(ABC):
    @abstractmethod
    def key_changed(self, old_key: 'Field', new_key: 'Field', child_node) -> None:
        """Callback method for when a child node's leftmost key changes."""
