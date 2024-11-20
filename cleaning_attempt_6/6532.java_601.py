import unittest
from ghidra_test_utils import ProjectTestUtils


class SaveToolTest(unittest.TestCase):

    DIRECTORY_NAME = ProjectTestUtils.get_test_directory_path()
    TOOL_NAME = "TestTool"

    def setUp(self):
        ProjectTestUtils.delete_project(DIRECTORY_NAME, self.TOOL_NAME)
        self.project = ProjectTestUtils.get_project(DIRECTORY_NAME, self.TOOL_NAME)

    def tearDown(self):
        self.project.close()
        ProjectTestUtils.delete_project(DIRECTORY_NAME, self.TOOL_NAME)

    def test_save_tool(self):

        # Make sure old tool instance does not exist
        tool_chest = self.project.get_local_tool_chest()
        if TOOL_NAME in [tool.name for tool in tool_chest]:
            tool_chest.remove(TOOL_NAME)

        # create a new running tool
        from ghidra_test_utils import run_swing
        def get_running_tool():
            return ProjectTestUtils.get_tool(self.project, None)
        run_swing(get_running_tool())

        self.running_tool = get_running_tool()

        try:
            # set the name of the tool to what the user will enter in a "Save" dialog
            self.running_tool.set_tool_name(TOOL_NAME)

            # save the tool to the project tool chest
            ProjectTestUtils.save_tool(self.project, self.running_tool)

            # verify the project tool chest now contains the saved tool
            if TOOL_NAME not in [tool.name for tool in tool_chest]:
                self.fail(f"{TOOL_NAME} was not saved to tool chest!")

        finally:
            from ghidra_test_utils import run_swing
            def close_running_tool():
                self.running_tool.close()
            run_swing(close_running_tool)

            if TOOL_NAME in [tool.name for tool in tool_chest]:
                tool_chest.remove(TOOL_NAME)
            ProjectTestUtils.delete_tool(self.project, TOOL_NAME)


if __name__ == "__main__":
    unittest.main()
