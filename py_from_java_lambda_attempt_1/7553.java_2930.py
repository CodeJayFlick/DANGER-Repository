Here is the translation of the Java code into Python:

```Python
class UngroupVertexFunctionGraphJob:
    def __init__(self, controller, group_vertex, use_animation, is_part_of_ungroup_all):
        super().__init__(controller, group_vertex, group_vertex.get_vertices(), {group_vertex}, False, use_animation)
        self.duration = NORMAL_DURATION if not is_part_of_ungroup_all else FAST_DURATION

    def notify_group_change(self):
        self.get_function_graph().group_removed(self.group_vertex)

    def get_grouping_destination_locations(self, is_relayout, group_vertex_destination_location):
        if is_relayout:
            return {}
        # note: we don't need to worry about the group vertex here, as its position doesn't change
        return self.group_vertex.get_pre_group_locations()

    def initialize_vertex_locations(self):
        positions = update_destination_locations()
        vertex_destination_locations = positions.get_vertex_locations()
        final_edge_articulations = positions.get_edge_articulations()

        old_location = to_location(self.group_vertex)
        group_vertex_point = old_location.clone()

        vertices_to_move = self.get_vertices_to_move()
        for vertex in vertices_to_move:
            current_point
            if new_vertices.contains(vertex):
                # not in the layout yet, we have to use the group as the starting point
                current_point = group_vertex_point.clone()
            else:
                current_point = to_location(vertex)

            start_point = current_point.clone()
            destination_point = vertex_destination_locations.get(vertex).clone()
            transition_points = TransitionPoints(start_point, destination_point)
            self.vertex_locations.put(vertex, transition_points)

        for vertex in new_vertices:
            start_point = group_vertex_point.clone()
            x_point = self.vertex_locations.get(vertex)
            x_point.start_point = start_point

        edge_articulations = positions.get_edge_articulations()
        edges_to_move = self.graph.get_edges()
        for edge in edges_to_move:
            current_articulations = edge.get_articulation_points()
            new_articulations = edge_articulations.get(edge)
            if new_articulations is None:
                new_articulations = []

            transition_points = get_articulation_transition_points(current_articulations, new_articulations, vertex_destination_locations, edge)

            self.edge_articulation_locations.put(edge, transition_points)

    def get_articulation_transition_points(self, current_articulations, new_articulations, destination_locations, edge):
        if len(current_articulations) > len(new_articulations):
            return get_articulation_transition_points_when_starting_with_more_points(current_articulations, new_articulations, destination_locations, edge)
        return get_articulation_transition_points_when_starting_with_less_points(current_articulations, new_articulations, destination_locations, edge)

    def get_articulation_transition_points_when_starting_with_more_points(self, current_articulations, new_articulations, destination_locations, edge):
        transition_points = []

        for i in range(len(current_articulations)):
            start_point = current_articulations[i]
            end_point = start_point.clone()
            if i < len(new_articulations):
                # prefer the new articulations, while we have some
                end_point = new_articulations[i]
            else:
                # less articulations in the new layout--map to the destination point of the destination vertex
                destination_vertex = edge.get_end()
                transition_points_destination = get_transition_point(self.vertex_locations, destination_locations, destination_vertex)
                end_point = transition_points_destination.destination_point

            transition_points.append(ArticulationTransitionPoints(start_point, end_point))

        return transition_points

    def get_articulation_transition_points_when_starting_with_less_points(self, current_articulations, new_articulations, destination_locations, edge):
        transition_points = []

        # 
        # In this case we will have to add articulations to the current edge now so that we can animate their creation.
        #
        new_start_articulations_points = []

        default_to_start_vertex_so_to_handle_the_case_where_we_started_with_no_articulations
        last_valid_start_point = to_location(edge.get_start())
        for i in range(len(new_articulations)):
            end_point = new_articulations[i]

            start_point = last_valid_start_point.clone()
            if i < len(current_articulations):
                # prefer the new articulations, while we have some
                start_point = current_articulations[i]
                last_valid_start_point = start_point

            transition_points.append(ArticulationTransitionPoints(start_point, end_point))
            new_start_articulations_points.append(start_point)

        edge.set_articulation_points(new_start_articulations_points)

        return transition_points

    def get_transition_point(self, transition_points, destination_locations, vertex):
        # make sure the original vertex is in the graph (it may have been grouped)
        function_graph = self.get_function_graph()
        ignore = [self.group_vertex]
        vertex = function_graph.find_matching_vertex(vertex, ignore)

        if transition_points.get(vertex) is not None:
            return transition_points.get(vertex)

        # We have a destination vertex that is not being moved, so it is not in the 'transitionPoints'.  Create a TransitionPoint for it.
        return create_transition_point(destination_locations, vertex)

    def create_transition_point(self, destination_locations, vertex):
        current_point = to_location(vertex)
        start_point = current_point.clone()

        end_point = destination_locations.get(vertex)
        if end_point is None:
            # this can happen when the vertex is the group vertex being removed; just use the start point
            end_point = start_point

        destination_point = end_point.clone()
        return TransitionPoints(start_point, destination_point)

class ArticulationTransitionPoints:
    def __init__(self, start_point, end_point):
        self.start_point = start_point
        self.end_point = end_point

class TransitionPoints:
    def __init__(self, start_point, end_point):
        self.start_point = start_point
        self.destination_point = end_point