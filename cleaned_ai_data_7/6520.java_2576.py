import os
from unittest import TestCase


class AddViewToProjectTest(TestCase):

    DIRECTORY_NAME = 'test_directory'
    PROJECT_NAME1 = 'TestAddViewToProject'
    PROJECT_VIEW1 = 'TestView1'
    PROJECT_VIEW2 = 'TestView2'

    def setUp(self):
        try:
            for project in [self.PROJECT_NAME1, self.PROJECT_VIEW1, self.PROJECT_VIEW2]:
                os.remove(os.path.join(self.DIRECTORY_NAME, f'{project}.ghidra'))
        except FileNotFoundError:
            pass

    def tearDown(self):
        try:
            for project in [self.PROJECT_NAME1, self.PROJECT_VIEW1, self.PROJECT_VIEW2]:
                os.remove(os.path.join(self.DIRECTORY_NAME, f'{project}.ghidra'))
        except FileNotFoundError:
            pass

    def test_add_to_view(self):

        # make sure we have projects to use as the project view...
        for project in [self.PROJECT_VIEW1, self.PROJECT_VIEW2]:
            os.remove(os.path.join(self.DIRECTORY_NAME, f'{project}.ghidra'))

        # get project (create it if it doesn't exist...)
        project = 'TestAddViewToProject'
        try:
            view_url = f'file://{os.path.join(self.DIRECTORY_NAME, self.PROJECT_VIEW1)}'
            os.mkdir(os.path.join(self.DIRECTORY_NAME, project))
            with open(os.path.join(self.DIRECTORY_NAME, project, 'ghidra'), 'w') as file:
                pass
            # add another view that will be removed to test the remove
            os.mkdir(os.path.join(self.DIRECTORY_NAME, self.PROJECT_VIEW2))

            # validate the view was added to project
            proj_views = [os.path.join(self.DIRECTORY_NAME, project), os.path.join(self.DIRECTORY_NAME, self.PROJECT_VIEW1)]
            for proj_view in proj_views:
                print(f"added view: {proj_view}")

            # remove the view...
            os.rmdir(os.path.join(self.DIRECTORY_NAME, self.PROJECT_VIEW2))
            print(f"removed view: {view_url}")

        finally:
            try:
                os.remove(os.path.join(self.DIRECTORY_NAME, project, 'ghidra'))
            except FileNotFoundError:
                pass
