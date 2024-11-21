class AbstractGraphVisibilityTransitionJob:
    def __init__(self, viewer: 'VisualGraphViewer', use_animation: bool):
        self.use_animation = use_animation
        self.viewer = viewer
        self.graph = viewer.get_visual_graph()

        if is_too_big_to_animate():
            self.use_animation = False

    @staticmethod
    def non_null(collection) -> list:
        return [item for item in collection] if collection else []

    def set_percent_complete(self, percent_complete: float):
        print(f"setPercentComplete() callback: {percent_complete}")
        self.update_opacity(percent_complete)
        self.viewer.repaint()

    def create_animator(self) -> Animator or None:
        if not self.use_animation:
            return None

        new_animator = PropertySetter.create_animator(
            duration=self.duration, target=self, property_name="percent_complete", start_value=0.0, end_value=1.0
        )
        new_animator.set_acceleration(0)
        new_animator.set_deceleration(0.8)

        return new_animator

    def finished(self):
        self.set_percent_complete(1.0)
        self.viewer.repaint()

    def update_opacity(self, percent_complete: float) -> None:
        pass  # By default we don't change opacity for just moving vertices around.

    @staticmethod
    def get_edges(vertices: list or set, vertex_type=VisualVertex):
        return {edge for edge in (vertex.get_incident_edges() if isinstance(vertex, vertex_type) else [] for vertex in vertices)}

    def is_too_big_to_animate(self) -> bool:
        return len(self.graph.get_vertices()) >= TOO_BIG_TO_ANIMATE

class Animator:
    pass  # This class needs to be implemented.

# Note: The above Python code does not include the actual implementation of classes like 'VisualGraphViewer', 'VisualVertex' and 'Animator'. These need to be defined separately.
