class VisualVertexSatelliteRenderer:
    def __init__(self):
        pass

    def paint_icon_for_vertex(self, rc: RenderContext, v: V, layout: Layout) -> None:
        default_graphics = rc.get_graphics_context()
        if v.is_selected():
            shape = self.get_full_shape(rc, layout, v)
            bounds = shape.get_bounds()
            self.paint_highlight(rc, v, default_graphics, bounds)

        emphasis = v.get_emphasis()
        if emphasis == 0:
            super().paint_icon_for_vertex(rc, v, layout)
            return

    def prepare_final_vertex_shape(self, rc: RenderContext, v: V, layout: Layout, coords: list) -> Shape:
        # DEBUG original behavior; this can show the true shape of the vertex
        # return super().prepare_final_vertex_shape(rc, v, layout, coords)

        # use the compact shape in the satellite view        
        return self.get_compact_shape(rc, layout, v)

    def paint_highlight(self, rc: RenderContext, vertex: V, graphics: GraphicsDecorator, bounds: Rectangle) -> None:
        if not vertex.is_selected():
            return

        old_paint = graphics.get_paint()

        halfish_transparency = 150
        yellow_with_transparency = Color(255, 255, 0, halfish_transparency)
        graphics.set_paint(yellow_with_transparency)

        offset = 10

        # scale the offset with the scale of the view, but not as fast, so that as we scale down,
        # the size of the paint area starts to get larger than the vertex
        offset = int(self.adjust_value_for_current_scale(rc, offset, .9))
        graphics.fill_oval(bounds.x - offset, bounds.y - offset, 
                           bounds.width + (offset * 2), 
                           bounds.height + (offset * 2))

        if self.is_graph_scaled_enough_to_be_difficult_to_see(rc):
            graphics.set_color(Color.BLACK)
            graphics.draw_oval(bounds.x - offset, bounds.y - offset, 
                               bounds.width + (offset * 2) + 2, 
                               bounds.height + (offset * 2) + 2)
            graphics.draw_oval(bounds.x - offset - 1, bounds.y - offset - 1, 
                               bounds.width + (offset * 2) + 4, 
                               bounds.height + (offset * 2) + 4)

        graphics.set_paint(old_paint)

    def is_graph_scaled_enough_to_be_difficult_to_see(self, rc: RenderContext) -> bool:
        scale = self.get_scale(rc)
        return scale < .05

class GraphicsDecorator:
    pass
