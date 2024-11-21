import tkinter as tk
from PIL import ImageTk, Image

class ToggleNavigationAid:
    ENABLED_ICON = None
    CANCEL_ICON = None
    DISABLED_ICON = None

    showing_navigation_aid = True

    def __init__(self):
        self.put_value("small_icon", SelfPaintingIcon())
        self.put_value("short_description",
            "Paints an on-screen marker to show the current location when navigating within the help system")

        translated_icon = CenterTranslateIcon(CANCEL_ICON, ENABLED_ICON.width)
        disabled_base_icon = ResourceManager.get_disabled_icon(ENABLED_ICON, 50)
        DISABLED_ICON = MultiIcon(disabled_base_icon, translated_icon)

        value = Preferences.get_property("SHOW_AID_KEY")
        if value is not None:
            self.showing_navigation_aid = bool(value)
        else:
            # not yet in the preferences; save the default
            self.save_preference()

    def action_performed(self):
        self.showing_navigation_aid = not self.showing_navigation_aid
        self.save_preference()

    def save_preference(self):
        Preferences.set_property("SHOW_AID_KEY", str(self.showing_navigation_aid))
        Preferences.store()

class SelfPaintingIcon:
    def paint_icon(self, c, g, x, y):
        icon = self.get_icon()
        icon.paint_icon(c, g, x, y)

    def get_icon(self):
        return self.showing_navigation_aid and ENABLED_ICON or DISABLED_ICON

    def get_icon_width(self):
        return self.get_icon().width()

    def get_icon_height(self):
        return self.get_icon().height()
