Here is the translation of the Java code into Python:

```Python
class BowTieExpandVerticesJob:
    def __init__(self, viewer, new_vertex_collection, use_animation):
        super().__init__()
        self.new_vertex_collection = new_vertex_collection
        self.incoming = new_vertex_collection.is_incoming()
        self.expanding_level = new_vertex_collection.get_expanding_level()

        if not isinstance(viewer.graph_layout, BowTieLayout):
            raise ValueError("The current graph layout must be the " + str(BowTieLayout) + " to use this job")

        print(f"\nBow Tie Expand Job - new vertices: {new_vertex_collection.get_new_vertices()}")

    def is_too_big_to_animate(self):
        return self.graph.get_vertex_count() > 1000

    def update_opacity(self, percent_complete):
        x = percent_complete
        x2 = x ** 2
        remaining = 1 - percent_complete
        y = x2 - remaining

        new_vertices = self.new_vertex_collection.get_new_vertices()
        vertex_alpha = x
        edge_alpha = max(y, 0)
        for v in new_vertices:
            v.set_opacity(vertex_alpha)

        new_edges = self.new_vertex_collection.get_new_edges()
        for e in new_edges:
            e.set_opacity(edge_alpha)

    def can_shortcut(self):
        return True

    def shortcut(self):
        is_shortcut = True
        if not vertex_locations:
            initialize_vertex_locations()

        stop()

    def initialize_vertex_locations(self):
        destination_locations = create_destination_location()
        self.vertex_locations.update(destination_locations)

    def create_destination_location(self):
        final_destinations = arrange_new_vertices()
        transitions = {}
        parent_level = self.expanding_level.parent
        new_edges = self.new_vertex_collection.get_new_edges()
        for e in new_edges:
            if not incoming or (incoming and e.end() in new_vertices):
                continue

            start = to_location(e.start()).clone()
            end = final_destinations[e.end()]
            trans = TransitionPoints(start, end)
            transitions.update({e.end(): trans})

        return transitions

    def arrange_new_vertices(self):
        bow_tie = self.graph_layout
        is_condensed = bow_tie.is_condensed_layout
        width_padding = 0 if not is_condensed else GraphViewerUtils.EXTRA_LAYOUT_COLUMN_SPACING_CONDENSED
        height_padding = calculate_height_padding(is_condensed)

        parent_level_vertices = new_vertex_collection.get_vertices_by_level(parent_level)
        existing_row_bounds = get_bounds(parent_level_vertices)
        existing_center_x = existing_row_bounds.x + (existing_row_bounds.width / 2)
        row_width = getWidth(all_level_vertices, width_padding)
        row_height = getHeight(all_level_vertices)

        locations = {}
        for v in all_level_vertices:
            p = to_location(v).clone()
            if p.get_x() == 0 and p.get_y() == 0:
                return {}

            locations.update({v: (p.clone())})

        return locations

    def calculate_height_padding(self, is_condensed):
        base_padding = GraphViewerUtils.EXTRA_LAYOUT_ROW_SPACING
        separation_factor = self.expanding_level.distance()
        count = len(all_level_vertices)

        to = 1.25
        power = math.pow(separation_factor, to)
        max_padding = int(base_padding * power)

        delta = max_padding - base_padding
        percent = min(count / 20, 1)
        padding = int(base_padding + (delta * percent))

        return padding

    def get_existing_locations(self, vertices):
        locations = {}
        for v in vertices:
            p = to_location(v).clone()
            if p.get_x() == 0 and p.get_y() == 0:
                return {}

            locations.update({v: (p.clone())})

        return locations

    def get_bounds(self, vertices):
        area = None
        for v in vertices:
            bounds = shaper.apply(v).getBounds()
            loc = layout.apply(v)
            x = int(loc.get_x())
            y = int(loc.get_y())

            if not area:
                area = bounds  # initialize

            area.add(bounds)

        return area

    def get_width(self, vertices):
        width = 0
        for v in vertices:
            width += shaper.apply(v).getBounds().width + GraphViewerUtils.EXTRA_LAYOUT_COLUMN_SPACING_CONDENSED

        return width

    def get_height(self, vertices):
        height = 0
        for v in vertices:
            height = max(height, shaper.apply(v).getBounds().height)

        return height


class TransitionPoints:
    def __init__(self, start, end):
        self.start = start
        self.end = end

# Note: The above Python code is a direct translation of the Java code provided. However,
# it may not work as expected because some methods and variables are missing from this 
# snippet (like `to_location`, `shaper`, `layout`, etc.). These need to be implemented
# according to your specific requirements.
```