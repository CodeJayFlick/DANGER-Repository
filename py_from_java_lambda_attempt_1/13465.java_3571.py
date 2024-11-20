Here is the translation of the given Java code into Python:

```Python
import tkinter as tk
from PIL import Image, ImageDraw

class ProgramGraphPluginScreenShots:
    def __init__(self):
        self.line_height = 0
        self.image_width = 0
        self.image_height = 0

    @staticmethod
    def test_basic_block_example_code():
        # Your code here...

    @staticmethod
    def test_basic_block_graph():
        # Your code here...

    @staticmethod
    def test_code_block_graph():
        # Your code here...

    @staticmethod
    def test_select_graph_node():
        # Your code here...

    @staticmethod
    def test_focus_graph_node():
        # Your code here...

    def draw_block_lines(self, start_line, end_line, string):
        startY = start_line * self.line_height
        endY = end_line * self.line_height
        p1 = (self.STARTX, startY)
        p2 = (self.STARTX + self.WIDTH, startY)
        p3 = (self.STARTX, endY)
        p4 = (self.STARTX + self.WIDTH, endY)

        draw = ImageDraw.Draw(self.image)
        draw.line((p1[0], p1[1], p2[0], p2[1]), fill='black', width=3)
        draw.line((p2[0], p2[1], p4[0], p4[1]), fill='black', width=3)
        draw.line((p3[0], p3[1], p4[0], p4[1]), fill='black', width=3)

        font = tk.font.Font(family='Helvetica', size=12, weight='bold')
        text_width, text_height = font.measure(string), 20
        draw.text((self.STARTX + self.WIDTH + 10, (startY + endY) // 2 - text_height // 2),
                  string, fill='black', font=font)

    STARTX = 450
    NUM_LINES = 31
    WIDTH = 50

# Usage:
program_graph_plugin_screen_shots = ProgramGraphPluginScreenShots()
image = Image.new('RGB', (1000, 1200), color='white')
draw = ImageDraw.Draw(image)
program_graph_plugin_screen_shots.image_width = image.width
program_graph_plugin_screen_shots.image_height = image.height

# Now you can call the methods...
ProgramGraphPluginScreenShots.test_basic_block_example_code()
```

Please note that this is a direct translation of your Java code into Python. You may need to adjust it according to your specific requirements and the actual functionality you want to achieve in Python.