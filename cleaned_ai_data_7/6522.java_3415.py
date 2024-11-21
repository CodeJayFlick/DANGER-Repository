import os
from unittest import TestCase


class CreateProjectTest(TestCase):

    def setUp(self):
        self.test_dir = get_test_directory_path()
        delete_project(self.test_dir, 'PROJECT_NAME')

    def tearDown(self):
        delete_project(self.test_dir, 'PROJECT_NAME')

    def test_create_project(self):
        url = ProjectLocator(self.test_dir, 'PROJECT_NAME')
        pm = TestProjectManager.get()

        try:
            pm.delete_project(url)
        except Exception as e:
            pass

        project = pm.create_project(url, None, True)

        if not project:
            self.fail("project is null!!!")

        p = project.project_locator
        if not p:
            self.fail(f"Project URL for {project.name} is null!")

        tc = project.local_tool_chest
        if not tc:
            self.fail("tool chest is null!!!")
        tm = project.tool_manager
        if not tm:
            self.fail("tool manager is null!!!")

        project.close()


def get_test_directory_path():
    # implement this function to return the test directory path
    pass


def delete_project(directory, name):
    # implement this function to delete a project in given directory with given name
    pass


class ProjectLocator:
    def __init__(self, directory, name):
        self.directory = directory
        self.name = name

    @property
    def project_locator(self):
        return f"{self.directory}/{self.name}"


class TestProjectManager:
    @staticmethod
    def get():
        # implement this function to return the test project manager instance
        pass


if __name__ == "__main__":
    unittest.main()
