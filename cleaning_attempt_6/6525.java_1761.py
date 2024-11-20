import unittest
from ghidra import ProgramBuilder
from tempfile import TemporaryDirectory

class ChangeToolDataTest(unittest.TestCase):

    def setUp(self):
        self.project = None
        with TemporaryDirectory() as tmpdir:
            project_path = f"{tmpdir}/project"
            # setup the running tool
            from dummy_tool import DummyTool
            self.running_tool = DummyTool()

    def tearDown(self):
        if self.project is not None:
            self.project.close()
        del self.project

    @unittest.skipIf(not hasattr(unittest, 'main'), "Not supported in Python < 3.2")
    def test_change_tool_data(self):

        data1 = ProgramBuilder("TestData1", ProgramBuilder._TOY).getProgram().getDomainFile()
        if not self.running_tool.accept_domain_files([data1]):
            self.fail("FAILED ChangeToolData Without Data")

        # TEST 2: set the data for a tool already running with data
        data2 = ProgramBuilder("TestData2", ProgramBuilder._TOY).getProgram().getDomainFile()
        if not self.running_tool.accept_domain_files([data2]):
            self.fail("FAILED ChangeToolData With Data")


if __name__ == '__main__':
    unittest.main()
