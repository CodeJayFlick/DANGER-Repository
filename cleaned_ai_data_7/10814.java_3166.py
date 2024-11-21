class GraphSatelliteListener:
    def __init__(self):
        pass

    def satellite_visibility_changed(self, docked: bool, visible: bool) -> None:
        """
        Called when the visibility and/or docked state of the watched satellite changes.

        Args:
            docked (bool): True if the satellite is now docked.
            visible (bool): True if the satellite is now visible.
        """
        pass
