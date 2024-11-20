class FunctionGraphGroupVertices3Test:
    def setUp(self):
        super().setUp()
        self.disable_animation()

    @staticmethod
    def disable_animation():
        pass  # Not implemented in this test case.

    @staticmethod
    def graph_function(function_address):
        pass  # Not implemented in this test case.

    @staticmethod
    def vertex(address):
        return None

    @staticmethod
    def group(name, *vertices):
        return None

    @staticmethod
    def ungroup(vertex):
        pass  # Not implemented in this test case.

    @staticmethod
    def regroup(vertex):
        pass  # Not implemented in this test case.

    @staticmethod
    def set_group_text(grouped_vertex, text):
        pass  # Not implemented in this test case.

    @staticmethod
    def assert_group_text(grouped_vertex, expected_text):
        pass  # Not implemented in this test case.

    @staticmethod
    def create12345Graph():
        pass  # Not implemented in this test case.

    @staticmethod
    def verify_edge(vertex1, vertex2):
        pass  # Not implemented in this test case.

    @staticmethod
    def verify_edges_count(count):
        pass  # Not implemented in this test case.

    @Test
    def test_adding_to_group(self):
        graph_data = self.graph_function("01002cf5")
        function_graph = graph_data.get_function_graph()
        graph = function_graph

        original_edges = list(graph.edges())
        ungrouped_vertices = select_vertices(function_graph, "01002d2b", "01002d1f")

        for vertex in ungrouped_vertices:
            self.ungroup(vertex)

        grouped_vertex = validate_new_grouped_vertex_from_vertices(
            function_graph, ungrouped_vertices
        )

        new_ungrouped_vertices = select_vertices(function_graph, "01002d66")
        new_edges = list(graph.edges())

        for vertex in new_ungrouped_vertices:
            self.ungroup(vertex)

        updated_grouped_vertex = validate_new_grouped_vertex_from_vertices(
            function_graph, ungrouped_vertices
        )

    @Test
    def test_adding_to_group_with_automatic_relayout_off(self):
        pass  # Not implemented in this test case.

    @Test
    def test_for_missing_edges_when_adding_to_group_bug(self):
        graph_function("0100415a")

        v1 = self.vertex("0100415a")
        v2 = self.vertex("01004178")
        v3 = self.vertex("01004192")
        v4 = self.vertex("01004196")
        v5 = self.vertex("0100419c")

        self.verify_edge(v1, v2)
        self.verify_edge(v2, v3)
        self.verify_edge(v1, v3)
        self.verify_edge(v3, v4)
        self.verify_edge(v3, v5)

        group = self.group("A", v1, v2)

        self.verify_edge(group, v3)
        self.verify_edge(group, v3)
        self.verify_edge(v3, v4)
        self.verify_edge(v3, v5)

        grouped_vertex = self.add_to_group(group, v3)

        self.verify_edge(grouped_vertex, v4)
        self.verify_edge(grouped_vertex, v5)

        self.ungroup_all()

        self.verify_edge(v1, v2)
        self.verify_edge(v2, v3)
        self.verify_edge(v1, v3)
        self.verify_edge(v3, v4)
        self.verify_edge(v3, v5)

    @Test
    def test_grouping_properly_translates_edges_from_grouped_vertices_to_real_vertices(self):
        create12345Graph()

        v1 = self.vertex("100415a")
        v2 = self.vertex("1004178")
        v3 = self.vertex("1004192")
        v4 = self.vertex("1004196")
        v5 = self.vertex("100419c")

        self.verify_edge(v1, v2)
        self.verify_edge(v2, v3)
        self.verify_edge(v3, v4)
        self.verify_edge(v3, v5)

        group_a = self.group("A", v1, v2)
        group_b = self.group("B", v3, v4)

        self.verify_edge(group_a, group_b)
        self.verify_edge(group_b, v5)
        self.verify_edge_count(2)  # No other edges

        group_z = self.group("Z", group_b, v5)

        self.verify_edge(group_a, group_z)
        self.verify_edge_count(1)

        self.ungroup(group_a)

        self.verify_edge(v1, v2)
        self.verify_edge(v2, group_z)
        self.verify_edge_count(2)

        self.ungroup(group_z)

        self.verify_edge(v1, v2)
        self.verify_edge(v2, v3)
        self.verify_edge(v3, v4)
        self.verify_edge(v3, v5)
        self.verify_edge_count(4)

    @Test
    def test_group_history_persistence(self):
        function_address = "01002cf5"
        graph_function(function_address)

        a1 = "1002d11"
        a2 = "1002d06"

        v1 = self.vertex(a1)
        v2 = self.vertex(a2)

        group_a = self.group("A", v1, v2)

        self.uncollapse(group_a)
        assert_uncollapsed(v1, v2)

        trigger_persistence_and_reload(function_address)
        wait_for_busy_graph()

        v1 = self.vertex(a1)
        v2 = self.vertex(a2)
        assert_uncollapsed(v1, v2)  # Group history restored

    @Test
    def test_group_history_persistence_with_other_group(self):
        function_address = "01002cf5"
        graph_function(function_address)

        a1 = "1002d11"
        a2 = "1002d06"

        v1 = self.vertex(a1)
        v2 = self.vertex(a2)

        group_a = self.group("A", v1, v2)

        self.uncollapse(group_a)
        assert_uncollapsed(v1, v2)

        a3 = "1002d1f"
        a4 = "1002d66"

        v3 = self.vertex(a3)
        v4 = self.vertex(a4)

        group_b = self.group("B", v3, v4)

        assert_uncollapsed(v1, v2)  # Sanity check

        trigger_persistence_and_reload(function_address)
        wait_for_busy_graph()

        v1 = self.vertex(a1)
        v2 = self.vertex(a2)
        assert_uncollapsed(v1, v2)  # Group history restored
        assert_grouped(v3, v4)  # Group restored

    @Test
    def test_history_updates_when_group_user_text_changes(self):
        create12345GraphWithTransaction()

        v1 = self.vertex("100415a")
        v2 = self.vertex("1004178")

        group_a = self.group("A", v1, v2)

        v3 = self.vertex("1004192")
        v4 = self.vertex("1004196")

        group_b = self.group("B", v3, v4)

        ungroup(group_a)
        regroup(v1)  # Regroup the inner group

        new_text = "New Inner Group Text"
        set_group_text(group_a, new_text)

        ungroup(group_a)
        regroup(v1)  # Regroup the inner group again

        assert_group_text(group_a, new_text)


if __name__ == "__main__":
    unittest.main()
