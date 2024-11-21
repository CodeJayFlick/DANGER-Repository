import tkinter as tk
from PIL import Image, ImageTk

class PointMarkerSet:
    def __init__(self):
        self.image = None
        self.fill_color = None

    def create(self, navigation_manager, name, desc, priority, show_markers, 
               show_navigation, color_background, marker_color, icon, program):
        super().__init__()
        if icon is None:
            icon = ResourceManager.load_image("images/warning.png")
        icon = ResourceManager.get_scaled_icon(icon, 16, 16)
        self.image = ImageTk.PhotoImage(icon)
        if marker_color is not None:
            self.fill_color = get_fill_color(marker_color)

    def create(self, navigation_manager, name, desc, priority, show_markers, 
               show_navigation, color_background, marker_color, icon, program):
        this(navigation_manager, name, desc, priority, show_markers, 
             show_navigation, color_background, marker_color, icon, True, program)

    def do_paint_markers(self, g, pixmap, index, map, layouts):
        if layouts is None:
            return
        for i in range(len(layouts)):
            y_start = pixmap.get_mark_position(i)
            cur_image = self.get_marker_image(pixmap, i, y_start)
            g.paste(cur_image, 0, y_start)

    def get_marker_image(self, pixmap, i, y_start):
        if marker_descriptor is None:
            return self.image
        address = pixmap.get_layout_address(i)
        program = mgr.get_program()
        loc = MarkerLocation(this, program, address, 0, y_start)
        icon = marker_descriptor.get_icon(loc)
        if icon is not None:
            return ImageTk.PhotoImage(icon)
        return self.image

    def do_paint_navigation(self, g, height, width, range_list):
        if range_list is None:
            return
        for r in range_list:
            start_y = r.min
            end_y = r.max
            if (end_y - start_y) % 2 != 0:
                end_y -= 1
            for y in range(end_y, start_y-1, -2):
                paint_y = min(height-MARKER_HEIGHT, y)
                g.fill_color(self.fill_color)
                g.rectangle(0, paint_y, width-MARKER_WIDTH_OFFSET, MARKER_HEIGHT)
                g.draw_rectangle(0, paint_y, width-MARKER_WIDTH_OFFSET, MARKER_HEIGHT)

    def get_nav_icon(self):
        buffered_image = Image.new('RGBA', (14, 14))
        graphics = ImageDraw.Draw(buffered_image)
        height = MarkerSetImpl.MARKER_HEIGHT
        width = 2 * height
        x = (14 - width) // 2
        y = (14 - height) // 2

        graphics.rectangle((x-1, y-1), (width+2, height+2))
        return ImageTk.PhotoImage(buffered_image)
