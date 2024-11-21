from abc import ABCMeta, abstractmethod
import math
import random

class VisualEdgeRenderer(metaclass=ABCMeta):
    def __init__(self):
        self.dashing_pattern_offset = 0.0
        self.default_base_color = (0, 0, 0)
        self.default_highlight_color = (128, 128, 128)

    @abstractmethod
    def set_dashing_pattern_offset(self, dashing_patter_offset: float) -> None:
        pass

    def set_base_color(self, color: tuple) -> None:
        self.default_base_color = color

    def get_base_color(self, graph: dict, e: any) -> tuple:
        return self.default_base_color

    def set_highlight_color(self, highlight_color: tuple) -> None:
        self.default_highlight_color = highlight_color

    def get_highlight_color(self, graph: dict, e: any) -> tuple:
        return self.default_highlight_color

    @abstractmethod
    def draw_simple_edge(self, rc: RenderContext, layout: Layout, e: any) -> None:
        pass


class VisualEdgeArrowRenderingSupport:
    def create_arrow_transform(self, rc: RenderContext, edge_shape: Shape, vs2: Shape) -> AffineTransform:
        return None

    @abstractmethod
    def get_vertex_shape_for_arrow(self, rc: RenderContext, layout: Layout, v: any) -> Shape:
        pass


class VisualEdgeRenderer(VisualEdgeRenderer):
    def __init__(self):
        super().__init__()
        self.arrow_rendering_support = VisualEdgeArrowRenderingSupport()

    @abstractmethod
    def get_edge_shape(self, rc: RenderContext, graph: dict, e: any, x1: float, y1: float,
                       x2: float, y2: float, is_loop: bool, vs1: Shape) -> Shape:
        pass

    def set_dashing_pattern_offset(self, dashing_patter_offset: float) -> None:
        self.dashing_pattern_offset = dashing_patter_offset

    @abstractmethod
    def get_hovered_path_stroke(self, e: any, scale: float) -> BasicStroke:
        pass

    @abstractmethod
    def get_focused_path_stroke(self, e: any, scale: float) -> BasicStroke:
        pass

    @abstractmethod
    def get_selected_stroke(self, e: any, scale: float) -> BasicStroke:
        pass

    @abstractmethod
    def get_emphasis_stroke(self, e: any, scale: float) -> BasicStroke:
        pass

    def scale_arrow_for_better_visibility(self, rc: RenderContext, arrow: Shape) -> Shape:
        view_transformer = rc.get_multi_layer_transformer().get_transformer(0)
        return view_transformer.create_transformed_shape(arrow)

    @abstractmethod
    def get_full_shape(self, rc: RenderContext, layout: Layout, vertex: any) -> Shape:
        pass

    @abstractmethod
    def transform_from_layout_to_view(self, rc: RenderContext, layout: Layout, vertex: any,
                                        shape: Shape) -> Shape:
        pass


class VisualEdgeArrowRenderingSupport(VisualEdgeArrowRenderingSupport):
    @abstractmethod
    def get_vertex_shape_for_arrow(self, rc: RenderContext, layout: Layout, v: any) -> Shape:
        pass

