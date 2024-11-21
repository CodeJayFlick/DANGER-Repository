Here is the equivalent Python code:

```Python
import unittest

class TaskMonitorSplitterTest(unittest.TestCase):
    def setUp(self):
        self.base_monitor = {'progress': 0}

    def test_basic_use(self):
        monitors = TaskMonitorSplitter.split_task_monitor(self.base_monitor, 4)

        monitors[0]['progress'] = 1
        self.assertEqual(1, monitors[0]['progress'])
        self.assertAlmostEqual(self.base_monitor['progress'], 25)  # Assuming MONITOR_SIZE is 400

        monitors[0]['increment_progress'](2)
        self.assertAlmostEqual(self.base_monitor['progress'], 50)

        monitors[0]['set_progress'](10)
        self.assertAlmostEqual(self.base_monitor['progress'], 250)

    def test_max_settings(self):
        monitors = TaskMonitorSplitter.split_task_monitor(self.base_monitor, 4)

        monitors[0]['initialize'](100)
        monitors[0]['set_progress'](50)
        self.assertAlmostEqual(self.base_monitor['progress'], 125)  # Assuming MONITOR_SIZE is 400

        monitors[0]['set_maximum'](25)
        self.assertEqual(monitors[0]['maximum'], 25)
        self.assertAlmostEqual(self.base_monitor['progress'], 100)

        monitors[0]['set_maximum'](100)
        self.assertAlmostEqual(self.base_monitor['progress'], 125)  # Assuming MONITOR_SIZE is 400

if __name__ == '__main__':
    unittest.main()
```

Note that Python does not have direct equivalent of Java's `@Test` annotation. Instead, we use the `unittest.TestCase` class and define methods starting with `test_`. The `setUp` method is used to initialize objects before each test case.