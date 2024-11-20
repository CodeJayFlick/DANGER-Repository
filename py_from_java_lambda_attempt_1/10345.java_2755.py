Here is a translation of the Java code into equivalent Python code:

```Python
import tkinter as tk
from weakref import WeakSet


class GGlassPane:
    BUSY_CURSOR = "watch"
    DEFAULT_CURSOR = ""

    _systemGlassPanes = WeakSet()

    def __init__(self):
        self._isBusy = False
        self._nonBusyCursor = ""
        self._painters = []
        self._blockingMouseListener = None

        GGlassPane._systemGlassPanes.add(self)

    def add_painter(self, painter):
        self._painters.append(painter)
        self.repaint()

    def remove_painter(self, painter):
        if painter in self._painters:
            self._painters.remove(painter)
            self.repaint()

    def set_busy(self, isBusy):
        self._isBusy = isBusy
        self.show_busy_cursor(isBusy)

        if not isBusy and self._blockingMouseListener:
            self.canvas.deleteall()
        else:
            self.canvas.bind("<Button-1>", self.blocking_mouse_listener)

        self.repaint()

    @staticmethod
    def set_all_glass_panes_busy(isBusy):
        for glassPane in GGlassPane._systemGlassPanes:
            glassPane.set_busy(isBusy)

    def is_busy(self):
        return self._isBusy

    def show_busy_cursor(self, showBusyCursor):
        if showBusyCursor and not self.canvas.cursor() == "watch":
            self.canvas.config(cursor="watch")
            self._nonBusyCursor = ""
        elif not showBusyCursor:
            if self.canvas.cursor() != "":
                self.canvas.config(cursor="")
                self._nonBusyCursor = ""

    def paint(self, event):
        for painter in self._painters:
            painter.paint(self, event)

    def contains(self, x, y):
        return True

    @staticmethod
    def get_glass_pane(component):
        window = component.winfo_toplevel()
        if isinstance(window, tk.Tk) or isinstance(window, tk.Toplevel):
            glassPane = GGlassPane._systemGlassPanes.get(window)
            if not glassPane:
                Msg.error(GGlassPane.__class__, "GGlassPane not installed on window: " + str(window), new AssertException())
                return None
            else:
                return glassPane
        elif isinstance(window, tk.Toplevel):
            frame = window.winfo_toplevel()
            glassPane = GGlassPane._systemGlassPanes.get(frame)
            if not glassPane:
                Msg.error(GGlassPane.__class__, "GGlassPane not installed on window: " + str(window), new AssertException())
                return None
            else:
                return glassPane
        return None

    def __init__(self, master=None):
        super().__init__()
        self.master = master
        self.pack()
```

Note that Python does not have direct equivalent of Java's Swing and AWT. So I used tkinter for GUI operations in the above code.