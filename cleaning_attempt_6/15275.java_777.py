import tkinter as tk
from PIL import ImageDraw, Image
import math

class ScannerView:
    def __init__(self):
        self.is_result = False
        self.dots = {}
        self.frame = None
        self.mask_color = (0x33, 0x33, 0x33)
        self.laser_color = (255, 0, 0)
        self.dot_color = (0, 255, 0)

    def set_framing(self, frame):
        self.frame = frame

    def set_is_result(self, is_result):
        self.is_result = is_result
        if hasattr(self, 'canvas'):
            self.canvas.delete('all')
            self.draw()

    def add_dot(self, dot):
        self.dots[dot] = math.floor(time.time())
        if hasattr(self, 'canvas'):
            self.canvas.delete('all')
            self.draw()

    def draw(self):
        canvas_width = 800
        canvas_height = 600

        if not hasattr(self, 'canvas'):
            self.canvas = tk.Canvas(tk.Tk(), width=canvas_width, height=canvas_height)
            self.canvas.pack()
        else:
            self.canvas.delete('all')

        for dot in list(self.dots.keys()):
            age = math.floor(time.time()) - self.dots[dot]
            if age < 500:  # TTL
                alpha = int((500-age) * 256 / 500)
                x, y = dot
                canvas_width_half = canvas_width // 2
                canvas_height_half = canvas_height // 2

                if (x - canvas_width_half)**2 + (y - canvas_height_half)**2 > ((canvas_width_half+20)*(canvas_height_half+20)):
                    self.canvas.create_oval(x-5, y-5, x+5, y+5, fill=(0,255,0), outline=self.dot_color)
                else:
                    if age < 250:  # laser phase
                        alpha = int((500-age) * 256 / 500)
                        self.canvas.create_line(0, canvas_height_half, canvas_width, canvas_height_half, fill=self.laser_color, width=5)
            else:
                del self.dots[dot]

        if self.is_result:  # draw mask and result
            for x in range(canvas_width):
                for y in range(canvas_height):
                    if (x - canvas_width // 2)**2 + (y - canvas_height // 2)**2 > ((canvas_width // 2+20)*(canvas_height // 2+20)):
                        self.canvas.create_oval(x-5, y-5, x+5, y+5, fill=self.mask_color)
            for x in range(canvas_width):
                for y in range(canvas_height):
                    if (x - canvas_width // 2)**2 + (y - canvas_height // 2)**2 > ((canvas_width // 2+20)*(canvas_height // 2+20)):
                        self.canvas.create_oval(x-5, y-5, x+5, y+5, fill=self.laser_color)
        else:  # draw mask and laser
            for x in range(canvas_width):
                for y in range(canvas_height):
                    if (x - canvas_width // 2)**2 + (y - canvas_height // 2)**2 > ((canvas_width // 2+20)*(canvas_height // 2+20)):
                        self.canvas.create_oval(x-5, y-5, x+5, y+5, fill=self.mask_color)
            for t in range(6):
                angle = math.pi * (t % 4) / 2
                end_x = int(math.cos(angle)) * canvas_width // 2 + canvas_width // 2
                end_y = -int(math.sin(angle)) * canvas_height // 2 + canvas_height // 2
                self.canvas.create_line(0, canvas_height_half, end_x, end_y, fill=self.laser_color)

        self.canvas.update()
