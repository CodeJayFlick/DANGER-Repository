class GroupVertexFunctionGraphJob:
    def __init__(self, controller, group_vertex, location=None, relayout_override=False,
                 use_animation=True, is_regroup_operation=False):
        super().__init__(controller, group_vertex)
        self.function_graph = controller.get_function_graph_data().get_function_graph()
        self.group_vertex_current_location = location
        self.is_regroup_operation = is_regroup_operation

    @staticmethod
    def create_new_group_job(controller, group_vertex, location, relayout_override,
                              use_animation):
        return GroupVertexFunctionGraphJob(controller, group_vertex, location,
                                             relayout_override, use_animation)

    @staticmethod
    def create_regroup_job(controller, group_vertex, location, relayout_override,
                            use_animation):
        return GroupVertexFunctionGraphJob(controller, group_vertex, location,
                                             relayout_override, use_animation, True)

    @staticmethod
    def create_update_group_job(controller, group_vertex, vertices_to_group,
                                 use_animation):
        return GroupVertexFunctionGraphJob(controller, group_vertex, vertices_to_group,
                                             use_animation)

    def notify_group_change(self):
        if self.is_regroup_operation:
            self.function_graph.group_restored(self.group_vertex)
        else:
            self.function_graph.group_added(self.group_vertex)

    def get_grouping_destination_locations(self, is_relayout, group_vertex_destination_location=None):
        if group_vertex_destination_location is None:
            group_vertex_destination_location = self.group_vertex_current_location

        locations = {}
        for vertex in self.vertices_to_be_removed:
            locations[vertex] = group_vertex_destination_location
        if not is_relayout:
            locations[self.group_vertex] = group_vertex_destination_location
        return locations

    def initialize_vertex_locations(self):
        positions = update_destination_locations()
        destination_locations = positions.get_vertex_locations()
        final_edge_articulations = positions.get_edge_articulations()

        vertices_to_move = self.get_vertices_to_move()
        for vertex in vertices_to_move:
            current_point = graph_layout.apply(vertex)
            start_point = current_point.clone()
            end_point = destination_locations[vertex].clone()
            transition_points = TransitionPoints(start_point, end_point)
            vertex_locations.put(vertex, transition_points)

        edge_articulations = positions.get_edge_articulations()
        edges_to_move = self.graph.get_edges()
        for edge in edges_to_move:
            current_articulations = edge.get_articulation_points()
            new_articulations = edge_articulations[edge]
            if new_articulations is None:
                new_articulations = []
            transition_points = get_articulation_transition_points(current_articulations,
                                                                    new_articulations, destination_locations, edge)
            edge_articulation_locations.put(edge, transition_points)

    def get_articulation_transition_points(self, current_articulations, new_articulations,
                                             destination_locations, edge):
        if len(current_articulations) > len(new_articulations):
            return self.get_articulation_transition_points_when_starting_with_more_points(
                current_articulations, new_articulations, destination_locations, edge)
        else:
            return self.get_articulation_transition_points_when_starting_with_less_points(
                current_articulations, new_articulations, destination_locations, edge)

    def get_articulation_transition_points_when_starting_with_more_points(self,
                                                                           current_articulations,
                                                                           new_articulations,
                                                                           destination_locations,
                                                                           edge):
        transition_points = []
        for i in range(len(current_articulations)):
            start_point = current_articulations[i]
            end_point = start_point.clone()
            if i < len(new_articulations):
                end_point = new_articulations[i]
            else:
                vertex = edge.get_end()
                destination_transition_point = get_transition_point(vertex_locations,
                                                                      destination_locations, vertex)
                end_point = destination_transition_point.destination_point
            transition_points.append(ArticulationTransitionPoints(start_point, end_point))
        return transition_points

    def get_articulation_transition_points_when_starting_with_less_points(self,
                                                                           current_articulations,
                                                                           new_articulations,
                                                                           destination_locations,
                                                                           edge):
        transition_points = []
        last_valid_start_point = graph_layout.apply(edge.get_start())
        for i in range(len(new_articulations)):
            end_point = new_articulations[i]
            start_point = last_valid_start_point.clone()
            if i < len(current_articulations):
                start_point = current_articulations[i]
                last_valid_start_point = start_point
            transition_points.append(ArticulationTransitionPoints(start_point, end_point))
        edge.set_articulation_points(transition_points)
        return transition_points

    def get_transition_point(self, vertex_locations, destination_locations, vertex):
        transition_point = vertex_locations.get(vertex)
        if transition_point is not None:
            return transition_point
        else:
            return self.create_transition_point(destination_locations, vertex)

    def create_transition_point(self, destination_locations, vertex):
        current_point = graph_layout.apply(vertex)
        start_point = current_point.clone()
        end_point = destination_locations[vertex].clone()
        return TransitionPoints(start_point, end_point)


class TransitionPoints:
    def __init__(self, start_point, end_point):
        self.start_point = start_point
        self.end_point = end_point


class ArticulationTransitionPoints(TransitionPoints):
    pass

# usage example:

controller = ...  # your controller object
group_vertex = ...  # your group vertex object
location = ...  # your location point
relayout_override = False
use_animation = True
is_regroup_operation = False

job = GroupVertexFunctionGraphJob.create_new_group_job(controller, group_vertex,
                                                         location, relayout_override, use_animation)
