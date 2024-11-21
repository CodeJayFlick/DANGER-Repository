class FGVertexRenderer:
    def paint_drop_shadow(self, rc, g, shape, vertex):
        bounds = shape.getBounds()
        if isinstance(vertex, GroupedFunctionGraphVertex):
            original_bounds = bounds.clone()
            vertices = vertex.getVertices()
            offset = 15
            size = len(vertices)
            if size > 3:
                size //= 3
                size = max(size, 2)
            current_offset = offset * size
            for i in range(size - 1, -1, -1):
                paint_bounds = original_bounds.clone()
                paint_bounds.x += current_offset
                paint_bounds.y += current_offset
                current_offset -= offset
                super().paint_drop_shadow(rc, g, paint_bounds)
        super().paint_drop_shadow(rc, g, bounds)

    def paint_vertex_or_vertex_shape(self, rc, g, layout, vertex, compact_shape, full_shape):
        if self.is_scaled_past_vertex_painting_threshold(rc):
            self.paint_scaled_vertex(rc, vertex, g, compact_shape)
            return
        if isinstance(vertex, GroupedFunctionGraphVertex):
            original_bounds = full_shape.getBounds()
            paint_bounds = original_bounds.clone()
            vertices = vertex.getVertices()
            offset = 5
            size = len(vertices)
            if size > 3:
                size //= 3
                size = max(size, 2)  # we want at least 2, to give some depth
            current_offset = offset * size
            for i in range(size - 1, -1, -1):
                paint_bounds.x += current_offset
                paint_bounds.y += current_offset
                current_offset -= offset
                self.paint_vertex(rc, g, vertex, paint_bounds, layout)
        # paint one final time
        bounds = full_shape.getBounds()
        self.paint_vertex(rc, g, vertex, bounds, layout)

    def paint_vertex(self, rc, g, vertex, bounds, layout):
        self.refresh_vertex_as_needed(vertex)
        vertex.set_showing(True)  # hack to make sure the component paints 
        super().paint_vertex(rc, g, vertex, bounds, layout)
        vertex.set_showing(False)  # turn off painting (this fix keeps tooltips from painting)

    def refresh_vertex_as_needed(self, vertex):
        vertex.refresh_model()

    def is_scaled_past_vertex_painting_threshold(self, rc):
        pass

    def paint_scaled_vertex(self, rc, vertex, g, compact_shape):
        pass
