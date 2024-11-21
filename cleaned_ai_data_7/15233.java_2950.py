import math

class CircularProgressView:
    def __init__(self):
        self.width = 0
        self.height = 0
        self.progress = 1
        self.max_progress = 1
        self.size = 1
        self.max_size = 1
        self.path = None
        self.fill_paint = None
        self.stroke_paint = None

    def set_colors(self, fill_color, stroke_color):
        if not self.fill_paint:
            self.fill_paint = {'style': 'fill', 'color': fill_color}
        else:
            self.fill_paint['color'] = fill_color

        if not self.stroke_paint:
            self.stroke_paint = {'style': 'stroke', 'color': stroke_color, 'width': 1}
        else:
            self.stroke_paint['color'] = stroke_color
            self.stroke_paint['width'] *= math.sqrt(2)

    def set_progress(self, progress):
        if not hasattr(self, 'progress'):
            self.progress = progress

        self.update_path()
        self.invalidate()

    def set_max_progress(self, max_progress):
        if not hasattr(self, 'max_progress'):
            self.max_progress = max_progress

        self.update_path()
        self.invalidate()

    def set_size(self, size):
        if not hasattr(self, 'size'):
            self.size = size

        self.update_path()
        self.invalidate()

    def set_max_size(self, max_size):
        if not hasattr(self, 'max_size'):
            self.max_size = max_size

        self.update_path()
        self.invalidate()

    def update_path(self):
        abs_size = min(self.width, self.height) / 2
        size = self.size < self.max_size and math.min(abs_size * self.size / self.max_size, abs_size - 1) or abs_size - 1

        if not hasattr(self, 'path'):
            self.path = []

        if self.progress == 0:
            self.path.append('close')
        elif self.progress < self.max_progress:
            angle = (self.progress * 360 / self.max_progress)
            x = self.width / 2
            y = self.height / 2

            self.path.extend(['move_to', f'{x},{y}'])
            self.path.extend([f'arc_to', f'{x - size}, {y - size}, {x + size}, {y + size}', str(angle), '0.5'])

        else:
            self.path.append('add_circle')
            if not hasattr(self, 'path'):
                self.path = []

    def on_draw(self):
        # This method is equivalent to the Java's onDraw
        pass

    def invalidate(self):
        # This method is equivalent to the Java's invalidate
        pass

    def get_baseline(self):
        return self.height - 1


class View:
    def __init__(self, context, attrs=None):
        if not hasattr(self, 'width'):
            self.width = 0
        if not hasattr(self, 'height'):
            self.height = 0

    def on_size_changed(self, w, h, oldw, oldh):
        # This method is equivalent to the Java's onSizeChanged
        pass


class Canvas:
    def draw_path(self, path, paint):
        # This method is equivalent to the Java's canvas.drawPath
        pass


if __name__ == '__main__':
    view = CircularProgressView()
