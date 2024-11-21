Here is the equivalent Python code:

```Python
import random
from collections import defaultdict, deque

class TokenHighlightColors:
    def __init__(self):
        self.min_color_saturation = 100
        self.default_color_alpha = 100
        self.colors_by_name = {}
        self.recent_colors = deque()

    def generate_color(self):
        return (
            random.randint(0, 256),
            random.randint(0, 256),
            random.randint(0, 256),
            self.default_color_alpha,
        )

    def get_color(self, text: str) -> tuple:
        if text not in self.colors_by_name:
            color = self.generate_color()
            self.colors_by_name[text] = color
        return self.colors_by_name.get(text)

    def set_color(self, text: str, color: tuple):
        self.colors_by_name[text] = color
        self.recent_colors.append(color)

    def get_recent_colors(self) -> list:
        return list(self.recent_colors)
```

Note that Python does not have a direct equivalent to Java's `HashMap` and `ArrayList`. Instead, we use the built-in dictionary (`defaultdict`) for storing colors by name and deque (a double-ended queue) for keeping track of recent colors.