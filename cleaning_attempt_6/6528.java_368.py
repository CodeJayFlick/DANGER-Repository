import unittest
from ghidra_test_utils import ProjectTestUtils

class CreateToolTest(unittest.TestCase):

    def setUp(self):
        PROJECT_NAME = 'test_project'
        directory_name = ProjectTestUtils.get_test_directory_path()
        project = ProjectTestUtils.get_project(directory_name, PROJECT_NAME)
        self.project = project

    def tearDown(self):
        if hasattr(self, 'project'):
            try:
                self.project.close()
            except Exception as e:
                print(f"Error closing the project: {e}")
        else:
            pass
        # Delete the project directory
        ProjectTestUtils.delete_project(directory_name, PROJECT_NAME)

    @unittest.skip("This test is not implemented yet")
    def test_create_tool(self):
        tool = None

        try:
            self.project.get_tool_manager().get_running_tools()
        except Exception as e:
            print(f"Error getting running tools: {e}")

        # Close the tool
        if hasattr(self, 'tool'):
            try:
                self.tool.close()
            except Exception as e:
                print(f"Error closing the tool: {e}")
