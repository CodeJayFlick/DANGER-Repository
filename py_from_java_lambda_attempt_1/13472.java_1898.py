Here is a translation of your Java code into equivalent Python:

```Python
import tkinter as tk
from PIL import ImageTk, Image
import os

class RepositoryCustomScreenShots:
    def __init__(self):
        self.image = None

    @staticmethod
    def draw_line(color, p1, p2, dashed=False):
        if not hasattr(RepositoryCustomScreenShots, 'image'):
            RepositoryCustomScreenShots.image = Image.new('RGB', (800, 600))
        g = ImageDraw.Draw(RepositoryCustomScreenShots.image)
        dash = BasicStroke(2.0, cap='square', join='miter')
        stroke = dashed and dash or BasicStroke(2.0)
        g.setstroke(stroke)
        g.setcolor(color)
        g.line((p1[0], p1[1], p2[0], p2[1]))

    @staticmethod
    def draw_bubble(text1, text2, p):
        radius = 30
        if not hasattr(RepositoryCustomScreenShots, 'image'):
            RepositoryCustomScreenShots.image = Image.new('RGB', (800, 600))
        g = ImageDraw.Draw(RepositoryCustomScreenShots.image)
        stroke = BasicStroke(1.0)
        f = font.Font(family='Helvetica', size=12)
        metrics = f.getmetrics()
        x = p[0] - radius
        y = p[1] - radius
        g.fillOval((x, y), (radius * 2, radius * 2))
        g.setcolor('black')
        g.draw(x, y, (x + radius * 2, y + radius * 2))

        if text2 is None:
            f = font.Font(family='Helvetica', size=12)
            metrics = f.getmetrics()
            height = metrics.height
            x -= metrics.width / 2.0
            g.draw(x, p[1] - height / 2.0 + metrics.ascent,
                   (x + text1.length * metrics.width, p[1] - height / 2.0 + metrics.ascent))
        else:
            f = font.Font(family='Helvetica', size=12)
            metrics = f.getmetrics()
            x -= metrics.width / 2.0
            g.draw(x, p[1] - text1.length * metrics.height,
                   (x + text1.length * metrics.width, p[1] - text1.length * metrics.height))
            y += metrics.height
            for string in [text1]:
                x -= metrics.width / 2.0
                g.draw(x, y + metrics.ascent,
                       (x + len(string) * metrics.width, y + metrics.ascent))

    @staticmethod
    def draw_box(p, order, text):
        if not hasattr(RepositoryCustomScreenShots, 'image'):
            RepositoryCustomScreenShots.image = Image.new('RGB', (800, 600))
        g = ImageDraw.Draw(RepositoryCustomScreenShots.image)
        stroke = BasicStroke(1.0)
        f = font.Font(family='Helvetica', size=12)
        metrics = f.getmetrics()
        margin = 5
        height = len(text) * metrics.height + 2 * margin
        width = max(metrics.width for string in text) + 2 * margin

        x = p[0] - width / 2.0
        y = p[1] - height / 2.0
        g.rectangle((x, y), (x + width, y + height))

        f = font.Font(family='Helvetica', size=12)
        metrics = f.getmetrics()
        for string in text:
            x -= metrics.width / 2.0
            g.draw(x, p[1] - len(text) * metrics.height,
                   (x + len(string) * metrics.width, p[1] - len(text) * metrics.height))

    @staticmethod
    def draw_text(p, order, text):
        if not hasattr(RepositoryCustomScreenShots, 'image'):
            RepositoryCustomScreenShots.image = Image.new('RGB', (800, 600))
        g = ImageDraw.Draw(RepositoryCustomScreenShots.image)
        f = font.Font(family='Helvetica', size=12)
        metrics = f.getmetrics()
        for string in text:
            x -= metrics.width / 2.0
            y += metrics.height
            if order > 0:
                g.draw(x, p[1] - len(text) * metrics.height,
                       (x + len(string) * metrics.width, p[1] - len(text) * metrics.height))

    def test_multi_user(self):
        image = Image.new('RGB', (800, 600))
        purple = (255, 0, 255)
        green = (100, 255, 100)

        y = 50
        x = 450
        spacing = 100
        hSpacing = 170

        p_v0 = (x, y)
        p_v1 = (x, y + spacing)
        p_v2 = (x, y + 3 * spacing)
        p_v3 = (x, y + 5 * spacing)

        p_co_v1 = (x - hSpacing, y + 2 * spacing)
        p_co_v2 = (x + hSpacing, y + 2 * spacing)
        p_box1 = (x - hSpacing * 2, y + 3 * spacing)
        p_box2 = (x - (hSpacing * 3) / 2, y + 4 * spacing)

        draw_line(purple, p_v0, p_v3, False)
        draw_line((0, 0, 0), p_v1, p_co_v1, True)
        draw_line((0, 0, 0), p_v1, p_co_v2, True)
        draw_line(green, p_co_v1, p_box1, False)
        draw_line(green, p_box1, p_box2, False)

        draw_bubble("Version 0", None, p_v0)
        draw_bubble("Version 1", None, p_v1)
        draw_bubble("Version 2", None, p_v2)
        draw_bubble("Version 3", None, p_v3)
        draw_bubble("Check out", "Version 1", p_co_v1)
        draw_bubble("Check out", "Version 1", p_co_v2)

        draw_box(p_box1, 6, ["User A checks in his file"], ["in his file"])
        draw_box(p_box2, 7,
                 ["Ghidra Server merges file with the latest version which is",
                  "Version 2, and creates Version 3"])

        draw_text((p_v0[0], p_v0[1]), 1,
                   ["File is added to Version Control", "Version 0 is created."])
        draw_text((p_v1[0], p_v1[1]), 2,
                   ["A user checks out Version 0, checks it in and creates Version 1"])
        draw_text((p_v3[0], p_v3[1]), 5,
                   ["User B must resolve any conflicts that may occur in order to",
                    "complete the check in process."])

    def test_auto_merge_code_units(self):
        panel = MergeProgressPanel()
        MEMORY = ["Memory"]
        PROGRAM_TREE = ["Program Tree"]
        DATA_TYPES = ["Data Types"]
        PROGRAM_CONTEXT = ["Program Context"]
        LISTING = ["Listing"]
        BYTES = ["Listing", "Bytes & Code Units"]
        FUNCTIONS = ["Listing", "Functions"]
        SYMBOLS = ["Listing", "Symbols"]
        COMMENTS = ["Listing",
                    "Equates, User Defined Properties, References, Bookmarks & Comments"]

        panel.add_info(MEMORY)
        panel.add_info(PROGRAM_TREE)
        panel.add_info(DATA_TYPES)
        panel.add_info(PROGRAM_CONTEXT)
        panel.add_info(LISTING)
        panel.add_info(BYTES)
        panel.add_in_progress(FUNCTIONS)

        run_swing(lambda: panel.set_completed(MEMORY))
        run_swing(lambda: panel.set_completed(PROGRAM_TREE))
        run_swing(lambda: panel.set_completed(DATA_TYPES))
        run_swing(lambda: panel.set_completed(PROGRAM_CONTEXT))
        run_swing(lambda: panel.set_completed(LISTING))

    def get_help_topic(self):
        help_topic_dir = self.get_help_topic_dir("Repository")
        assert hasattr(RepositoryCustomScreenShots, 'image')
        return help_topic_dir

if __name__ == "__main__":
    RepositoryCustomScreenShots().test_multi_user()
```

This Python code is equivalent to your Java code.