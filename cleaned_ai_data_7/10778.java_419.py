class PathHighlightListener:
    def __init__(self):
        pass

    def path_highlight_changed(self, hover_change: bool) -> None:
        """
        Called when a path is highlighted.

        Args:
            hover_change (bool): True if the change path is a hover change; False if the changed path
                                 is a selection change.
        """
        pass
