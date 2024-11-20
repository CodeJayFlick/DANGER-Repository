import android.graphics as ag
from kivy.app import App
from kivy.uix.widget import Widget
from kivy.properties import NumericProperty, ReferenceListProperty, ObjectProperty
from kivy.graphics import Color, Ellipse
from kivy.clock import Clock

class CircleClipTapView(Widget):
    def __init__(self, **kwargs):
        super(CircleClipTapView, self).__init__(**kwargs)
        
        self.background_paint = ag.Paint()
        self.circle_paint = ag.Paint()

        self.width_px = 0
        self.height_px = 0

        # Background
        self.shape_path = ag.Path()
        self.is_left = True

        self.cx = 0.0
        self.cy = 0.0

        self.current_radius = 0.0
        self.min_radius = 0
        self.max_radius = 0

    def update_position(self, x, y):
        self.cx = x
        self.cy = y
        
        new_is_left = x <= (self.width_px / 2)
        if self.is_left != new_is_left:
            self.is_left = new_is_left
            self.update_path_shape()

    def invalidate_with_current_radius(self, factor):
        self.current_radius = min_radius + (max_radius - min_radius) * factor
        self.canvas.ask_redraw()

    # Background
    def update_path_shape(self):
        half_width = self.width_px / 2.0

        self.shape_path.reset()
        
        w = self.is_left and 0 or self.width_px
        f = self.is_left and -1 or 1
        
        self.shape_path.move_to(w, 0)
        self.shape_path.line_to(f * (half_width - arc_size) + w, 0)
        self.shape_path.quad_to(
            f * (half_width + arc_size) + w,
            self.height_px / 2.0,
            f * (half_width - arc_size) + w,
            self.height_px
        )
        self.shape_path.line_to(w, self.height_px)
        self.shape_path.close()
        self.canvas.ask_redraw()

    # Animation
    def get_circle_animator(self):
        if not hasattr(self, 'value_animator'):
            self.value_animator = Clock.schedule_interval(lambda dt: self.invalidate_with_current_radius((dt % 1) * (max_radius - min_radius)), 0.01)
        
        return self.value_animator

    # Others
    def on_size_changed(self, w, h, oldw, oldh):
        super(CircleClipTapView, self).on_size_changed(w, h, oldw, oldh)
        self.width_px = w
        self.height_px = h
        self.update_path_shape()

    def on_draw(self, canvas):
        if canvas:
            canvas.clip_by_rect(0, 0, self.width_px, self.height_px)

        with self.canvas:
            Color(1, 1, 1)
            Ellipse(pos=(self.cx, self.cy), size=(2 * self.current_radius, 2 * self.current_radius))

class CircleClipTapApp(App):
    def build(self):
        return CircleClipTapView()

if __name__ == '__main__':
    CircleClipTapApp().run()
