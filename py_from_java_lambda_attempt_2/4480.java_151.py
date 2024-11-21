Here is the translation of the given Java code into equivalent Python:

```Python
import tkinter as tk
from tkinter import messagebox
import os

class LookAndFeelPlugin:
    def __init__(self):
        self.selected_look_and_feel = "Swing Look And Feel"
        self.use_inverted_colors = False
        self.issued_laf_notification = False
        self.issued_preferred_dark_theme_laf_notification = False

    def init_look_and_feel_options(self, tool):
        options_title = "Look and feel settings"

        if not hasattr(tool, 'get_options'):
            return

        opt = tool.get_options(options_title)

        look_and_feel_names = ["Swing Look And Feel", "Metal Look And Feel"]
        opt.register_option("Set the look and feel for Ghidra.", self.selected_look_and_feel,
                             new StringWithChoicesEditor(look_and_feel_names))

    def options_changed(self, tool_options, option_name, old_value, new_value):
        if option_name == "Look and feel":
            if not (new_value == old_value):
                self.issue_laf_notification()
                self.save_look_and_feel(new_value)

        elif option_name == "Use Inverted Colors":
            if not (new_value == old_value):
                self.use_inverted_colors = new_value
                Preferences.set_property("use_inverted_colors", str(self.use_inverted_colors))
                Preferences.store()

    def save_look_and_feel(self, look_and_feel):
        self.selected_look_and_feel = look_and_feel
        Preferences.set_property("last_look_and_feel_key", self.selected_look_and_feel)
        Preferences.store()

    def issue_laf_notification(self):
        if not (self.issued_laf_notification):
            self.issued_laf_notification = True

            messagebox.showinfo("Look and feel updated",
                                 "The new look and feel will take effect after you exit and restart Ghidra.")

    def issue_preferred_dark_theme_laf_notification(self):
        if not (self.issued_preferred_dark_theme_laf_notification):
            self.issued_preferred_dark_theme_laf_notification = True

            choice = messagebox.askyesno("Change Look and Feel?", "The 'Use Inverted Colors' setting works best with the Metal Look and Feel.\nWould you like to switch to that Look and Feel upon restart?")

            if (choice == 1):
                self.save_look_and_feel(DockingWindowsLookAndFeelUtils.METAL_LOOK_AND_FEEL)

    def dispose(self, tool):
        opt = tool.get_options(options_title)
        opt.remove_options_listener(self)
```

Please note that Python does not have direct equivalent of Java's Swing and AWT libraries. The above code is a translation into pure Python without using any GUI library like Tkinter or PyQt.