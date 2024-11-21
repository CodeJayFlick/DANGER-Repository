import math

class CenterAnimationJob:
    def __init__(self, viewer, old_point, new_point):
        self.viewer = viewer
        self.old_point = old_point
        self.new_point = new_point
        self.last_point = (old_point[0], old_point[1])

    @property
    def duration(self):
        return 1000

    def create_animator(self):
        from pydub.animation import PropertySetter, Animator
        animator = PropertySetter.create_animator(self.duration, self, 'percent_complete', 0.0, 1.0)
        animator.set_acceleration(0.0)
        animator.set_deceleration(0.8)

        return animator

    def set_percent_complete(self, percent_complete):
        journey_x = (self.new_point[0] - self.old_point[0]) * percent_complete
        journey_y = (self.new_point[1] - self.old_point[1]) * percent_complete

        new_x = self.old_point[0] + journey_x
        new_y = self.old_point[1] + journey_y

        delta_x = self.last_point[0] - new_x
        delta_y = self.last_point[1] - new_y

        self.last_point = (new_x, new_y)

        if math.isclose(delta_x, 0) and math.isclose(delta_y, 0):
            return

        transformer = self.viewer.get_render_context().get_multi_layer_transformer()
        transformer.translate(delta_x, delta_y)
        self.viewer.repaint()

    def finished(self):
        self.set_percent_complete(1.0)

# Example usage:
viewer = ... # Your viewer object
old_point = (10, 20)  # Old point coordinates
new_point = (30, 40)   # New point coordinates

job = CenterAnimationJob(viewer, old_point, new_point)
animator = job.create_animator()
