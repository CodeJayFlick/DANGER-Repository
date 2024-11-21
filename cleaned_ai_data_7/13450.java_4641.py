from PIL import Image, ImageDraw, Font
import math

class GlossaryScreenShots:
    def __init__(self):
        pass

    def draw_line(self, color, width, p1, p2):
        img = Image.new('RGB', (450, 100), 'white')
        d = ImageDraw.Draw(img)
        d.line((p1[0], p1[1], p2[0], p2[1]), fill=color, width=width)

    def draw_text(self, text, color, point, size):
        font = Font.truetype('arial.ttf', size)
        img = Image.new('RGB', (450, 100), 'white')
        d = ImageDraw.Draw(img)
        w, h = d.text_size(text, font=font)
        x = max(0, min(point[0], 450 - w))
        y = point[1]
        d.text((x, y), text, fill=color, font=font)

    def draw_arrow(self, color, width, p1, p2):
        img = Image.new('RGB', (450, 100), 'white')
        d = ImageDraw.Draw(img)
        x1, y1 = p1
        x2, y2 = p2
        dx = abs(x2 - x1)
        dy = abs(y2 - y1)

        if x1 < x2:
            arrow_x = 0.5 * dx
        else:
            arrow_x = -0.5 * dx

        if y1 < y2:
            arrow_y = 0.5 * dy
        else:
            arrow_y = -0.5 * dy

        p3 = (x1 + arrow_x, y1 + arrow_y)
        d.line((p1[0], p1[1], p2[0], p2[1]), fill=color, width=width)

    def draw_box(self):
        img = Image.new('RGB', (450, 100), 'white')
        d = ImageDraw.Draw(img)
        d.rectangle([(30, 10), (430, 50)], outline='black')

    def test_big_endian(self):
        self.draw_box()
        p1 = [30, 10]
        p2 = [430, 10]
        p3 = [430, 50]
        p4 = [30, 50]

        p5 = [225, 10]
        p6 = [225, 50]

        self.draw_line('black', 1, (p1[0], p1[1]), (p2[0], p2[1]))
        self.draw_line('black', 1, (p2[0], p2[1]), (p3[0], p3[1]))
        self.draw_line('black', 1, (p3[0], p3[1]), (p4[0], p4[1]))
        self.draw_line('black', 1, (p4[0], p4[1]), (p1[0], p1[1]))

        self.draw_line('black', 1, (p5[0], p5[1]), (p6[0], p6[1]))

        self.draw_text("high-order byte", 'black', [80, 35], 12)
        self.draw_text("low-order byte", 'black', [285, 35], 12)

        p7 = [30, 50]
        p8 = [30, 80]
        p9 = [225, 50]
        p10 = [225, 80]

        self.draw_arrow('black', 1, (p8[0], p8[1]), (p7[0], p7[1]))
        self.draw_arrow('black', 1, (p10[0], p10[1]), (p9[0], p9[1]))

        self.draw_text("addr A", 'black', [15, 93], 12)
        self.draw_text("addr A+1", 'black', [200, 93], 12)

    def test_little_endian(self):
        self.draw_box()
        p1 = [30, 10]
        p2 = [430, 10]
        p3 = [430, 50]
        p4 = [30, 50]

        p5 = [225, 10]
        p6 = [225, 50]

        self.draw_line('black', 1, (p1[0], p1[1]), (p2[0], p2[1]))
        self.draw_line('black', 1, (p2[0], p2[1]), (p3[0], p3[1]))
        self.draw_line('black', 1, (p3[0], p3[1]), (p4[0], p4[1]))
        self.draw_line('black', 1, (p4[0], p4[1]), (p1[0], p1[1]))

        self.draw_line('black', 1, (p5[0], p5[1]), (p6[0], p6[1]))

        self.draw_text("high-order byte", 'black', [80, 35], 12)
        self.draw_text("low-order byte", 'black', [285, 35], 12)

        p7 = [430, 50]
        p8 = [430, 80]
        p9 = [225, 50]
        p10 = [225, 80]

        self.draw_arrow('black', 1, (p8[0], p8[1]), (p7[0], p7[1]))
        self.draw_arrow('black', 1, (p10[0], p10[1]), (p9[0], p9[1]))

        self.draw_text("addr A+1", 'black', [200, 93], 12)
        self.draw_text("addr A", 'black', [413, 93], 12)

if __name__ == "__main__":
    gs = GlossaryScreenShots()
    gs.test_big_endian()
    gs.test_little_endian()

