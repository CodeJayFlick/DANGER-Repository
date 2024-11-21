Here is the translation of the Java code into Python:

```Python
import tkinter as tk
from PIL import ImageTk, Image

class NavigatableIconFactory:
    SNAPSHOT_ICON = None  # Initialize with None for now

    def create_snapshot_overlay_icon(self, primary_icon):
        new_outer_icon = MultiIcon(primary_icon)

        scaled_icon = self.get_scaled_icon(self.SNAPSHOT_ICON)
        highlight_icon = self.get_highlight_icon(scaled_icon)
        center_point = self.get_centered_icon_offset(highlight_icon, scaled_icon)
        highlight_multi_icon = MultiIcon(highlight_icon)
        highlight_multi_icon.add_icon(TranslateIcon(scaled_icon, center_point.x, center_point.y))

        lower_right_point = self.get_lower_right_icon_offset(primary_icon, highlight_multi_icon)
        new_outer_icon.add_icon(
            TranslateIcon(highlight_multi_icon, lower_right_point.x + 2, lower_right_point.y + 2))

        return ImageTk.Image(self.SNAPSHOT_ICON)

    def get_highlight_icon(self, primary_icon):
        primary_width = primary_icon.width
        primary_height = primary_icon.height
        color = (255, 255, 0)
        return self.get_image_icon(OvalColorIcon(color, primary_width + 4, primary_height + 4))

    def get_centered_icon_offset(self, primary_icon, overlay_icon):
        primary_width = primary_icon.width
        primary_height = primary_icon.height

        overlay_width = overlay_icon.width
        overlay_height = overlay_icon.height

        offset_x = (primary_width - overlay_width) // 2
        offset_y = (primary_height - overlay_height) // 2

        return Point(offset_x, offset_y)

    def get_lower_right_icon_offset(self, primary_icon, overlay_icon):
        primary_width = primary_icon.width
        primary_height = primary_icon.height

        overlay_width = overlay_icon.width
        overlay_height = overlay_icon.height

        return Point(primary_width - overlay_width, primary_height - overlay_height)


class MultiIcon:
    def __init__(self, icon):
        self.icon_list = [icon]

    def add_icon(self, new_icon):
        self.icon_list.append(new_icon)

    def get_icons(self):
        return self.icon_list


class TranslateIcon:
    def __init__(self, icon, x, y):
        self.icon = icon
        self.x = x
        self.y = y

    def get_x(self):
        return self.x

    def get_y(self):
        return self.y


class OvalColorIcon:
    def __init__(self, color, width, height):
        self.color = color
        self.width = width
        self.height = height

    def get_width(self):
        return self.width

    def get_height(self):
        return self.height


class Point:
    def __init__(self, x, y):
        self.x = x
        self.y = y

    def get_x(self):
        return self.x

    def get_y(self):
        return self.y


# Initialize SNAPSHOT_ICON for now. You should replace this with your actual image.
NavigatableIconFactory.SNAPSHOT_ICON = ImageTk.Image.open('images/camera-photo.png')
```

Please note that Python does not have direct equivalent of Java's `ImageIcon`, so I used PIL (Python Imaging Library) to load the images and create icons. Also, some methods like `ResourceManager.loadImage` are replaced with actual image loading code in this translation.