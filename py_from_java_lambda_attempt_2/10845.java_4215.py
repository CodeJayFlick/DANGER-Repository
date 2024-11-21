Here is the translation of the Java code into Python:

```Python
import turtle
from typing import List

class MouseDraggedLinePaintableShape:
    def __init__(self, start: tuple, end: tuple) -> None:
        self.points = [start, end]
        self.controls = []
        self.color = (0, 200/255, 0/255, 137/255)
        self.stroke_width = 20

    def add_point(self, p: tuple) -> None:
        self.points.append(p)
        self.build_shape()

    def build_shape(self) -> None:
        if len(self.points) == 2:
            start_x, start_y = self.points[0]
            end_x, end_y = self.points[1]
            path = turtle.RawPen()
            path.penup()
            path.goto(start_x, start_y)
            path.pendown()
            path.forward((end_x - start_x) / 2.5)
            path.right(90)
            path.forward((end_y - start_y) / 2.5)

        else:
            for i in range(len(self.points)):
                if i % 2 == 0:
                    x, y = self.points[i]
                    path.penup()
                    path.goto(x, y)
                    path.pendown()

    def paint(self):
        turtle.color(*self.color)
        turtle.width(self.stroke_width)

# Usage
shape = MouseDraggedLinePaintableShape((100, 200), (300, 400))
for _ in range(10):
    shape.add_point((150 + i*20, 250 + i*15) for i in range(5))

turtle.mainloop()
```

Please note that Python's turtle module is used to draw the shapes. It may not be exactly equivalent to Java's Graphics2D or GeneralPath classes.