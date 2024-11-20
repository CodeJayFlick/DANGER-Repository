from typing import TypeVar

V = TypeVar('V')
E = TypeVar('E')

class EnsureAreaVisibleAnimatorFunctionGraphJob(VirtualVertex, E):
    def __init__(self,
                 primary_viewer: VisualizationViewer[V, E],
                 satellite_viewer: SatelliteGraphViewer[V, E],
                 vertex: V,
                 visible_area: Rectangle,
                 use_animation: bool) -> None:
        super().__init__()
        self.satellite_viewer = satellite_viewer
        self.vertex = vertex
        self.visible_area = visible_area

    def create_animator(self) -> Animator:
        view_space_rectangle = GraphViewerUtils.translate_rectangle_from_vertex_relative_space_to_view_space(
            viewer=self.viewer,
            vertex=self.vertex,
            visible_area=self.visible_area)

        new_point = Point((view_space_rectangle.center_x, view_space_rectangle.center_y))

        vertex_bounds = GraphViewerUtils.get_vertex_bounds_in_view_space(viewer=self.viewer, vertex=self.vertex)
        vertex_center_x = (vertex_bounds.x + (vertex_bounds.width >> 1))
        new_point.x = vertex_center_x

        viewer_bounds = self.viewer.bounds
        if not viewer_bounds.contains(view_space_rectangle):
            pre_created_destination = new_point
            return super().create_animator()

        if not self.satellite_viewer.is_docked():
            return None  # cannot obscure if not docked

        if not self.satellite_viewer.is_showing():
            return None  # nothing to do

        satellite_bounds = self.satellite_viewer.bounds
        if not satellite_bounds.contains(view_space_rectangle):
            return None  # nothing to do

        pre_created_destination = new_point
        return super().create_animator()

    def create_destination(self) -> Point2D:
        if pre_created_destination is None:
            return None  # we chose not to change move the view
        return GraphViewerUtils.get_offset_from_center_for_point_in_view_space(
            viewer=self.viewer,
            point=pre_created_destination)

    def set_offset(self, offset: Point2D) -> None:
        if pre_created_destination is None:
            return  # This method gets called back after the animator is finished. If we chose not to do work, then just exit
        super().set_offset(offset)
