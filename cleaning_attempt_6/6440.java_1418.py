import unittest

class SelectByFlowPluginBackwardTest(unittest.TestCase):

    def testFollowAllFlowsBackFromSelection(self):
        selection_set = set()
        for i in range(0x131, 0x392, 4):
            selection_set.add(i)
        self.setSelection(selection_set)

        expected_addresses = set()
        for i in range(0x2e, 0x5008, 4):
            expected_addresses.add(i)
        expected_selection = ProgramSelection(expected_addresses)

        perform_action("selectAllFlowsToAction", get_action_context(), True)

        current_selection = code_browser_plugin.getCurrentSelection()

        self.assertEqual(MySelection(expected_selection), MySelection(current_selection))

    def testFollowAllFlowsBackFrom0x2f(self):
        go_to(0x2f)
        expected_addresses = set()
        for i in range(0, 0x5008, 4):
            expected_addresses.add(i)
        expected_selection = ProgramSelection(expected_addresses)

        perform_action("selectAllFlowsToAction", get_action_context(), True)

        current_selection = code_browser_plugin.getCurrentSelection()

        self.assertEqual(MySelection(expected_selection), MySelection(current_selection))

    def testAllLimitedFlowsBackFrom0x8f(self):
        flow_options = tool.getOptions(GhidraOptions.CATEGORY_FLOW_OPTIONS)
        turn_on_all_follow_flow(flow_options)
        go_to(0x8f)

        expected_addresses = set()
        for i in range(0, 0x5003, 4):
            expected_addresses.add(i)
        expected_selection = ProgramSelection(expected_addresses)

        perform_action("selectLimitedFlowsToAction", get_action_context(), True)

        current_selection = code_browser_plugin.getCurrentSelection()

        self.assertEqual(MySelection(expected_selection), MySelection(current_selection))

    def testAllLimitedFlowsBackFromEnd(self):
        flow_options = tool.getOptions(GhidraOptions.CATEGORY_FLOW_OPTIONS)
        turn_off_all_follow_flow(flow_options)

        selection_set = set()
        for i in range(0x130, 0x392, 4):
            selection_set.add(i)
        self.setSelection(selection_set)

        expected_addresses = set()
        for i in range(0, 0x5003, 4):
            expected_addresses.add(i)
        expected_selection = ProgramSelection(expected_addresses)

        perform_action("selectLimitedFlowsToAction", get_action_context(), True)

        current_selection = code_browser_plugin.getCurrentSelection()

        self.assertEqual(MySelection(expected_selection), MySelection(current_selection))

    def testFollowBackOnlyUnconditionalCalls(self):
        flow_options = tool.getOptions(GhidraOptions.CATEGORY_FLOW_OPTIONS)
        turn_off_all_follow_flow(flow_options)
        follow_unconditional_calls(True, flow_options)

        selection_set = set()
        for i in range(0x0a, 0x91, 4):
            selection_set.add(i)
        self.setSelection(selection_set)

        expected_addresses = set()
        for i in range(0, 0x2c, 4):
            expected_addresses.add(i)
        expected_selection = ProgramSelection(expected_addresses)

        perform_action("selectLimitedFlowsToAction", get_action_context(), True)

        current_selection = code_browser_plugin.getCurrentSelection()

        self.assertEqual(MySelection(expected_selection), MySelection(current_selection))

    def testFollowBackOnlyConditionalCalls(self):
        flow_options = tool.getOptions(GhidraOptions.CATEGORY_FLOW_OPTIONS)
        turn_off_all_follow_flow(flow_options)
        follow_conditional_calls(True, flow_options)

        selection_set = set()
        for i in range(0x0a, 0x91, 4):
            selection_set.add(i)
        self.setSelection(selection_set)

        expected_addresses = set()
        for i in range(0, 0x2e, 4):
            expected_addresses.add(i)
        expected_selection = ProgramSelection(expected_addresses)

        perform_action("selectLimitedFlowsToAction", get_action_context(), True)

        current_selection = code_browser_plugin.getCurrentSelection()

        self.assertEqual(MySelection(expected_selection), MySelection(current_selection))

    def testFollowBackOnlyComputedCalls(self):
        flow_options = tool.getOptions(GhidraOptions.CATEGORY_FLOW_OPTIONS)
        turn_off_all_follow_flow(flow_options)
        follow_computed_calls(True, flow_options)

        selection_set = set()
        for i in range(0x0a, 0x91, 4):
            selection_set.add(i)
        self.setSelection(selection_set)

        expected_addresses = set()
        for i in range(0, 0x2c, 4):
            expected_addresses.add(i)
        expected_selection = ProgramSelection(expected_addresses)

        perform_action("selectLimitedFlowsToAction", get_action_context(), True)

        current_selection = code_browser_plugin.getCurrentSelection()

        self.assertEqual(MySelection(expected_selection), MySelection(current_selection))

    def testFollowBackOnlyUnconditionalJumps(self):
        flow_options = tool.getOptions(GhidraOptions.CATEGORY_FLOW_OPTIONS)
        turn_off_all_follow_flow(flow_options)
        follow_unconditional_jumps(True, flow_options)

        selection_set = set()
        for i in range(0x0a, 0x91, 4):
            selection_set.add(i)
        self.setSelection(selection_set)

        expected_addresses = set()
        for i in range(0, 0x7, 1):
            expected_addresses.add(i)
        expected_selection = ProgramSelection(expected_addresses)

        perform_action("selectLimitedFlowsToAction", get_action_context(), True)

        current_selection = code_browser_plugin.getCurrentSelection()

        self.assertEqual(MySelection(expected_selection), MySelection(current_selection))

    def testFollowBackOnlyConditionalJumps(self):
        flow_options = tool.getOptions(GhidraOptions.CATEGORY_FLOW_OPTIONS)
        turn_off_all_follow_flow(flow_options)
        follow_conditional_jumps(True, flow_options)

        selection_set = set()
        for i in range(0x0a, 0x91, 4):
            selection_set.add(i)
        self.setSelection(selection_set)

        expected_addresses = set()
        for i in range(0, 0x2e, 1):
            expected_addresses.add(i)
        expected_selection = ProgramSelection(expected_addresses)

        perform_action("selectLimitedFlowsToAction", get_action_context(), True)

        current_selection = code_browser_plugin.getCurrentSelection()

        self.assertEqual(MySelection(expected_selection), MySelection(current_selection))

    def testFollowBackOnlyComputedJumps(self):
        flow_options = tool.getOptions(GhidraOptions.CATEGORY_FLOW_OPTIONS)
        turn_off_all_follow_flow(flow_options)
        follow_computed_jumps(True, flow_options)

        selection_set = set()
        for i in range(0x0a, 0x91, 4):
            selection_set.add(i)
        self.setSelection(selection_set)

        expected_addresses = set()
        for i in range(0, 0x2c, 1):
            expected_addresses.add(i)
        expected_selection = ProgramSelection(expected_addresses)

        perform_action("selectLimitedFlowsToAction", get_action_context(), True)

        current_selection = code_browser_plugin.getCurrentSelection()

        self.assertEqual(MySelection(expected_selection), MySelection(current_selection))

    def testFollowBackOnlyPointers(self):
        flow_options = tool.getOptions(GhidraOptions.CATEGORY_FLOW_OPTIONS)
        turn_off_all_follow_flow(flow_options)
        follow_pointers(True, flow_options)

        selection_set = set()
        for i in range(0x231, 0x332, 4):
            selection_set.add(i)
        self.setSelection(selection_set)

        expected_addresses = set()
        for i in range(0, 0x5003, 1):
            expected_addresses.add(i)
        expected_selection = ProgramSelection(expected_addresses)

        perform_action("selectLimitedFlowsToAction", get_action_context(), True)

        current_selection = code_browser_plugin.getCurrentSelection()

        self.assertEqual(MySelection(expected_selection), MySelection(current_selection))

    def testFollowBackOnlyPointers2(self):
        flow_options = tool.getOptions(GhidraOptions.CATEGORY_FLOW_OPTIONS)
        turn_off_all_follow_flow(flow_options)
        follow_pointers(True, flow_options)

        selection_set = set()
        for i in range(0x231, 0x332, 4):
            selection_set.add(i)
        self.setSelection(selection_set)

        expected_addresses = set()
        for i in range(0, 0x5003, 1):
            expected_addresses.add(i)
        expected_selection = ProgramSelection(expected_addresses)

        perform_action("selectLimitedFlowsToAction", get_action_context(), True)

        current_selection = code_browser_plugin.getCurrentSelection()

        self.assertEqual(MySelection(expected_selection), MySelection(current_selection))

if __name__ == '__main__':
    unittest.main()
