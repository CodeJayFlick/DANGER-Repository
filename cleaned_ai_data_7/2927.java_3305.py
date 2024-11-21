import unittest
from ghidra_framework_plugintool import PluginTool
from ghidra_graph_viewer_layout import VisualGraphLayout
from ghidra_test_abstract_g_hidra_headed_integration_test import AbstractGhidraHeadedIntegrationTest

class SampleGraphPluginTest(AbstractGhidraHeadedIntegrationTest):
    def setUp(self):
        self.env = TestEnv()
        tool = PluginTool(env=env)
        plugin = env.add_plugin(SampleGraphPlugin())
        show_provider_action = get_action(plugin, 'SHOW_PROVIDER_ACTION_NAME')
        perform_action(show_provider_action, True)
        provider = tool.get_component_provider('SampleGraphProvider')
        
    def tearDown(self):
        self.env.dispose()

    @unittest.skip
    def test_graph_gets_displayed(self):
        assert_true(provider.get_graph().get_vertex_count() > 10)

    @unittest.skip
    def test_change_layout_action(self):
        last_layout = get_current_layout()
        set_new_layout('Circle Layout')
        assert_not_same(last_layout, get_current_layout())

    @unittest.skip
    def test_filter(self):
        show_filter()
        enter_filter_text('Sample')
        # note: we are not testing the actual filter correctness, as there is already a unit 
        #       test covering that functionality.
        assert_some_vertices_filtered_out()
        assert_some_vertices_match_filter()

    def assert_some_vertices_filtered_out(self):
        graph = provider.get_graph()
        vertices = graph.get_vertices()
        has_filtered = any(v.alpha < 1.0 for v in vertices)
        self.assertTrue(has_filtered)

    def assert_some_vertices_match_filter(self):
        graph = provider.get_graph()
        vertices = graph.get_vertices()
        has_matches = any(double_compare(v.alpha, 1.0) == 0 for v in vertices)
        self.assertTrue(has_matches)

    def show_filter(self):
        filter_action = get_action(plugin, 'SHOW_FILTER_ACTION_NAME')
        set_toggle_action_selected(filter_action, provider.action_context(None), True)
        panel = find_component(provider.component(), "sample.graph.filter.panel")
        assert_not_none(panel)
        self.assertTrue(panel.is_showing())

    def enter_filter_text(self, text):
        text_field = find_component(provider.component(), JTextField)
        set_text(text_field, text)
        wait_for_swing()
        wait_for_busy_graph()

    def wait_for_busy_graph(self):
        updater = provider.graph_view_updater
        while updater.is_busy():
            pass

    def get_current_layout(self):
        graph = provider.get_graph()
        return graph.layout

    def set_new_layout(self, layout_name):
        relayout_action = get_action(plugin, 'RELAYOUT_GRAPH_ACTION_NAME')
        current_choice = relayout_action.current_state
        if current_choice.user_data.get_layout_name() == layout_name:
            self.fail(f"Layout already selected--pick a new layout '{layout_name}'")
        
        desired_choice = None
        choices = relayout_action.all_action_states
        for choice in choices:
            provider = choice.user_data
            if provider.get_layout_name() == layout_name:
                desired_choice = choice
                break
        
        assert_not_none("Could not find layout '" + layout_name + "'", desired_choice)
        
        the_choice = desired_choice
        run_swing(lambda: relayout_action.set_current_action_state(the_choice))
