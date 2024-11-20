Here is the translation of the Java code into Python:

```Python
import tkinter as tk
from tkinter import font
from threading import Thread

class ClearFilterLabel:
    def __init__(self, text_field):
        self.text_field = text_field
        self.transparency = 0.6
        self.animator = None
        
        # set the icon and tooltip for this label
        self.icon = Icons.DELETE_ICON.get()
        self.tooltip_text = "Clear filter"
        
    def clear_filter(self):
        self.text_field.delete(1, tk.END)
        if self.animator:
            self.cancel_animation()

    def paint_component(self, g):
        g2d = g.create_linear_gradient(self.transparency)
        super().paint_component(g)

    def set_transparency(self, transparency):
        self.transparency = transparency
        self.repaint()

    def show_filter_button(self):
        if not self.winfo_ismapped():
            return

        self.transparency = 0.6
        self.wm_state('normal')
        
        # reanimate the filter button
        Thread(target=self.reanimate).start()

    def reanimate(self):
        if not AnimationUtils.is_animation_enabled() or self.animator:
            return
        
        self.animator = PropertySetter.create_animator(1500, self, 'transparency', 0.6, 1)
        self.animator.set_acceleration(0)
        self.animator.set_deceleration(0.8)

    def cancel_animation(self):
        if self.animator:
            self.animator.cancel()
            self.animator = None

    def hide_filter_button(self):
        self.cancel_animation()
        self.wm_state('iconic')

    def reset_bounds(self):
        do_reset_bounds()

    def do_reset_bounds(self):
        parent = self.master
        text_bounds = self.text_field.winfo_rootx(), self.text_field.winfo_rooty(), self.text_field.winfo_width, self.text_field.winfo_height
        insets = self.text_field.winfo_xscrollbar().winfo_width + 2

        size = self.winfo_reqwidth()
        half = (text_bounds[3] - size) // 2
        y = text_bounds[1] + half
        
        end = text_bounds[0] + text_bounds[2]
        x = end - insets - size
        
        if touches_text(x):
            transparency = PARTIALLY_HIDDEN
        else:
            transparency = FULLY_OPAQUE

    def check_for_touchy_text(self, x):
        if self.touches_text(x):
            return
        elif transparency == PARTIALLY_HIDDEN:
            transparency = FULLY_OPAQUE

    def touches_text(self, x):
        fm = font.Font().metrics()
        text_bounds = self.text_field.winfo_rootx(), self.text_field.winfo_rooty(), self.text_field.winfo_width, self.text_field.winfo_height
        location = (text_bounds[0], text_bounds[1])
        
        text = self.text_field.get('1.0', tk.END)
        bounds = fm.measure(text)

        padding = 5
        if location[0] + bounds.width + padding > x:
            return True
        else:
            return False

class PropertySetter:
    @staticmethod
    def create_animator(duration, target, property_name, start_value, end_value):
        # implement the animation logic here
        pass

class AnimationUtils:
    @staticmethod
    def is_animation_enabled():
        # implement the animation enablement check here
        return True