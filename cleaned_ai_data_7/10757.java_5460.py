class MoveVertexToCenterAnimatorFunctionGraphJob:
    def __init__(self, viewer, vertex, use_animation):
        self.vertex = vertex
        super().__init__(viewer, use_animation)

    def create_destination(self):
        return GraphViewerUtils.get_vertex_offset_from_layout_center(viewer, self.vertex)
