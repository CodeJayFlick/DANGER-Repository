from typing import Any

class FieldOverlayListener:
    """Interface implemented by objects that want to be notified when an overlay is removed from the FieldPanel."""

    def field_overlay_removed(self, comp: Any) -> None:
        """
        Called when the an existing component is removed from the FieldPanel.
        
        :param comp: The overlay component that was removed.
        """
