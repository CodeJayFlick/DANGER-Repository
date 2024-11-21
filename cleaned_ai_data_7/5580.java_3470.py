class MarginProvider:
    def __init__(self):
        pass

    def get_component(self) -> object:
        """Get the component to show the margin markers."""
        raise NotImplementedError("Method not implemented")

    def is_resizeable(self) -> bool:
        """Return whether the component can be resized."""
        raise NotImplementedError("Method not implemented")

    def set_pixel_map(self, pixmap: dict):
        """Set the vertical pixel layout map.
        
        :param pixmap: The vertical pixel map to use.
        """
        pass

    def get_marker_location(self, x: int, y: int) -> object:
        """Get the marker location for the given x, y point.

        :param x: The horizontal coordinate.
        :param y: The vertical coordinate.
        """
        raise NotImplementedError("Method not implemented")
