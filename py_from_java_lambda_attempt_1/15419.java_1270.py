Here is the translation of the given Java code into Python:

```Python
class Rectangle:
    def __init__(self, point: tuple, width: float, height: float):
        self.width = width
        self.height = height
        self.corners = [point]
        self.corners.append((point[0] + width, point[1]))
        self.corners.append((point[0] + width, point[1] + height))
        self.corners.append((point[0], point[1] + height))

    def get_bounds(self):
        return self

    def get_path(self):
        return self.corners

    def get_point(self):
        return self.corners[0]

    def get_iou(self, box: 'Rectangle') -> float:
        rec = box
        # calculate intersection lrtb
        left = max(self.get_x(), rec.get_x())
        top = min(self.get_y(), rec.get_y())
        right = min(self.get_x() + self.width, rec.get_x() + rec.width)
        bottom = min(self.get_y() + self.height, rec.get_y() + rec.height)
        intersection = (right - left) * (bottom - top)
        return intersection / ((self.width * self.height) + (rec.width * rec.height) - intersection)

    def get_x(self):
        return self.corners[0][0]

    def get_y(self):
        return self.corners[0][1]

    def get_width(self):
        return self.width

    def get_height(self):
        return self.height

    def __str__(self):
        x, y = self.get_x(), self.get_y()
        return f"[x={x:.3f}, y={y:.3f}, width={self.width:.3f}, height={self.height:.3f}]"
```

Note: The `get_iou` method assumes that the input box is also a Rectangle.