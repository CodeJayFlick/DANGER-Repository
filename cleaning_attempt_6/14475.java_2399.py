import unittest
from your_module import Task, TaskHandler  # Replace 'your_module' with the actual name of your module


class TestTaskHandler(unittest.TestCase):

    def test_handle_task(self):
        task_handler = TaskHandler()
        handle = Task(100)
        task_handler.handle_task(handle)
        self.assertTrue(handle.is_finished())


if __name__ == '__main__':
    unittest.main()
