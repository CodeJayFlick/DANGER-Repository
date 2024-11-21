Here is the translation of the given Java code into Python:

```Python
class AreaMarkerSet:
    def __init__(self, marker_manager, name, desc, priority, show_markers, 
                 show_navigation, color_background, marker_color, program):
        super().__init__(marker_manager, program, name, desc, priority, 
                         show_markers, show_navigation, color_background, 
                         marker_color)

    @classmethod
    def from_marker_manager(cls, marker_manager, name, desc, priority, 
                             show_markers, show_navigation, color_background, 
                             marker_color, program):
        return cls(marker_manager, name, desc, priority, show_markers, 
                   show_navigation, color_background, marker_color, program)

    def do_paint_markers(self, pixmap, index, map, layouts):
        if not layouts:
            return

        for i in layouts:
            y_start = pixmap.get_begin_position(i)
            y_end = pixmap.get_end_position(i)
            self._paint_rect(7, y_start, 3, y_end - y_start + 1)

    def do_paint_navigation(self, range_list):
        if not range_list:
            return

        for range in range_list:
            start_y = range.min
            end_y = range.max
            len_ = end_y - start_y
            if len_ < MARKER_HEIGHT:
                len_ = MARKER_HEIGHT

            self._paint_rect(MARKER_WIDTH_OFFSET, start_y, 
                             MARKER_HEIGHT, len_)
    
    def get_nav_icon(self):
        image = BufferedImage(14, 14, BufferedImage.TYPE_INT_ARGB)
        g = image.create_graphics()

        height = MarkerSetImpl.MARKER_HEIGHT
        width = 2 * height
        x = (14 - width) // 2
        y = (14 - height) // 2

        self._paint_rect(x - 1, y - 1, width + 2, height + 2)

        return ResourceManager.get_image_icon_from_image("Area Marker Set Nav Icon", image)
```

Note: The above Python code is not a direct translation of the given Java code. It's more like an equivalent implementation in Python.