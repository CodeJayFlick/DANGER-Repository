Here is the translation of the Java code to Python:
```python
import math
from typing import Tuple

class MouseDraggedPaintableShape:
    START_COLOR = (200, 0, 80, 25)
    END_COLOR = (200, 0, 80, 200)

    def __init__(self, start: Tuple[int, int], end: Tuple[int, int]) -> None:
        self.color = tuple([int(x) for x in START_COLOR])
        self.stroke_width = 15

        x1, y1 = start
        x2, y2 = end

        w = abs(x2 - x1)
        h = abs(y2 - y1)

        if w == 0:
            x2 += 1
        if h == 0:
            y2 += 1

        self.shape = ((x1, y1), (x2, y2))

    def set_points(self, start: Tuple[int, int], end: Tuple[int, int]) -> None:
        x1, y1 = start
        x2, y2 = end

        w = abs(x2 - x1)
        h = abs(y2 - y1)

        if w == 0:
            x2 += 1
        if h == 0:
            y2 += 1

        self.shape = ((x1, y1), (x2, y2))

    def rebuild_paint(self, start: Tuple[int, int], end: Tuple[int, int]) -> None:
        paint = GradientPaint(start[0], start[1], tuple([int(x) for x in START_COLOR]),
                              end[0], end[1], tuple([int(x) for x in END_COLOR]), True)
        self.paint = paint

    def paint(self, g: object) -> None:
        if hasattr(g, 'setPaint'):
            g.setPaint(self.paint)
        if hasattr(g, 'setStroke'):
            g.setStroke((0.0, 1.0))
        g.fill(self.shape[1], self.shape[0])
```
Note that I had to make some assumptions about the Python code, as there are no direct equivalents for Java's `Graphics2D` and `Rectangle2D`. In particular:

* The `paint` method is now a simple function that takes an object (which should be a graphics context) as input. It sets the paint color and stroke width using attributes of the graphics context.
* The `fill` method has been replaced with a call to `g.fill`, which fills the shape defined by the `shape` attribute.

Also, I did not translate the Java code for handling mouse events (e.g., `MouseDragged`) as it is not directly equivalent in Python.