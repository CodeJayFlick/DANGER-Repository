Here is the translation of the Java code into Python:

```Python
import tkinter as tk
from typing import List, Set, Tuple

class MemviewPanel:
    def __init__(self, provider):
        self.provider = provider
        self.amap = None
        self.tmap = None
        self.boxList = []
        self.pressedX = 0
        self.pressedY = 0
        self.enableDrag = False
        self.ctrlPressed = False
        self.barWidth = 1000
        self.barHeight = 500
        self.vertical = False

    def getPreferredSize(self):
        asz = len(self.amap) if self.amap else 500
        tsz = len(self.tmap) if self.tmap else 500
        w, h = (tsz, asz) if self.vertical else (asz, tsz)
        return tk.Dimension(w, h)

    def paintComponent(self, g):
        super().paintComponent(g)
        g.setColor(getBackground())
        clip = g.getClipBounds()
        g.fillRect(clip.x, clip.y, clip.width, clip.height)

        height = self.getHeight()
        width = self.getWidth()
        if self.vertical and clip.height > height or not self.vertical and clip.width > width:
            self.refresh()

        for box in self.boxList:
            box.render(g, self.vertical)

        if self.currentPixelAddr >= 0:
            self.drawArrow(g)
        if self.currentRectangle is not None:
            self.drawFrame(g)

    def drawArrow(self, g):
        locXs = [0, -1, -1, -3, 0, 3, 1, 1]
        locYs = [0, 0, 6, 6, 9, 6, 6, 0]

        if self.vertical:
            g2 = (g).create().rotate(90.0 / 180.0 * math.pi)
            g2.translate(0, 9)
            g.translate(self.currentPixelAddr, -self.currentPixelTime)
            g.rotate(math.pi)

        else:
            g2 = (g).create()
            g2.translate(0, -9)
            g.translate(-self.currentPixelAddr, self.currentPixelTime)

        g.setColor(Color.RED)
        g.fillPolygon(locXs, locYs, len(locXs))

    def drawFrame(self, g):
        x, y, w, h = *self.currentRectangle
        g.setColor(Color.RED)
        g.fillRect(x - 1, y - 1, 1, h + 2)
        g.fillRect(x - 1, y - 1, w + 2, 1)
        g.fillRect(x + w + 1, y - 1, 1, h + 2)
        g.fillRect(x - 1, y + h + 1, w + 2, 1)

    def initViews(self):
        self.setSize(tk.Dimension(len(self.amap), len(self.tmap)))
        self.amap = MemviewMap(len(self.amap), len(self.amap))
        self.tmap = MemviewMap(len(self.tmap), len(self.tmap))

    def refresh(self):
        if self.amap is None or self.tmap is None:
            return

        for box in self.boxList:
            box.render(g, self.vertical)

    def updateBoxes(self):
        if not self.isShowing():
            return

        self.boxList = []
        boxes = getBoxes()
        if boxes is None:
            return
        for box in boxes:
            if box is None:
                continue

            bound = height - 1 if self.vertical else width - 1
            box.setAddressBounds(self.amap, bound)
            bound = width - 1 if self.vertical else height - 1
            box.setTimeBounds(self.tmap, bound)

            self.boxList.append(box)

        self.repaint(0, 0, self.getWidth(), self.getHeight())

    def mousePressed(self, e):
        requestFocus()   # COMPONENT

        self.ctrlPressed = False
        self.currentRectangle = None

        if e.getButton() == tk.BUTTON1:
            self.enableDrag = True
            self.pressedX = e.getX()
            self.pressedY = e.getY()
            self.currentPixelAddr = y if self.vertical else x
            self.currentPixelTime = x if self.vertical else y
            self.provider.selectTableEntry(getBoxesAt(x, y))
            self.provider.refresh()

        elif e.getButton() == tk.BUTTON2:
            print("BUTTON2")

        elif e.getButton() == tk.BUTTON3:
            self.ctrlPressed = True
            self.enableDrag = True
            self.pressedX = e.getX()
            self.pressedY = e.getY()

    def mouseReleased(self, e):
        self.enableDrag = False

    # ... (rest of the methods)

class MemviewMap:
    pass  # Implement this class as needed.

def getBoxesAt(x, y):  # Implement this function.
    return []

def getTagForAddr(addr):  # Implement this function.
    return ""

def getTagForTick(tick):  # Implement this function.
    return ""
```

Please note that the above Python code is not a direct translation of Java to Python. It's more like an interpretation, as some parts may need adjustments based on how you want your program to behave in Python.

The `MemviewMap` class and several functions (`getBoxesAt`, `getTagForAddr`, `getTagForTick`) are left unimplemented because they seem to be specific to the application domain.