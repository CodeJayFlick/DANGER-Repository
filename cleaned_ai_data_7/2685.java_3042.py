import tkinter as tk
from threading import Thread
import time


class ExpanderArrowPanel:
    ARROW = [(5, 0), (-5, -5), (-5, 5)]
    SIZE = (16, 16)
    ANIM_MILLIS = 80
    FRAME_MILLIS = 30

    def __init__(self):
        self.listeners = []
        self.expanded = False
        self.anim_theta = 0.0
        self.anim_active = False
        self.anim_time_end = None
        self.anim_theta_end = 0.0
        self.anim_theta_over_time_rate = 0.0

    def add_expansion_listener(self, listener):
        self.listeners.append(listener)

    def remove_expansion_listener(self, listener):
        if listener in self.listeners:
            self.listeners.remove(listener)

    def animate_theta(self, dest_theta):
        self.anim_time_end = time.time() + ANIM_MILLIS
        self.anim_theta_end = dest_theta
        self.anim_theta_over_time_rate = (dest_theta - self.anim_theta) / ANIM_MILLIS
        self.anim_active = True

    def toggle(self):
        if not self.expanded:
            self.set_expanded(True)
        else:
            self.set_expanded(False)

    def fire_changing(self, new_expanded):
        for listener in self.listeners:
            try:
                listener.changing(new_expanded)
            except Exception as e:
                return False
        return True

    def fire_changed(self):
        for listener in self.listeners:
            listener.changed(self.expanded)

    def set_expanded(self, expanded):
        if not (self.expanded == expanded):
            if not self.fire_changing(expanded):
                return
            dest_theta = 1.5708 if expanded else 0.0
            self.animate_theta(dest_theta)
            self.expanded = expanded
            self.fire_changed()

    def is_expanded(self):
        return self.expanded

    def paint_component(self, canvas):
        super().paint_component(canvas)

        g2d = canvas.create()
        g2d.setRenderingHint('antialiasing', True)
        g2d.translate(SIZE[0] / 2.0, SIZE[1] / 2.0)
        g2d.rotate(self.anim_theta)
        g2d.fill_polygon(*self.ARROW)

    def schedule_next_frame(self):
        Thread(target=self.repaint).start()

    def repaint(self):
        time.sleep(FRAME_MILLIS)
        self.canvas.repaint()


class ExpanderArrowExpansionListener:
    def changing(self, new_expanded):
        pass

    def changed(self, expanded):
        pass


if __name__ == "__main__":
    panel = ExpanderArrowPanel()
