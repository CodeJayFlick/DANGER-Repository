Here is the translation of the Java code into Python:

```Python
import threading
from queue import Queue
from typing import List, Dict, Any

class ConditionTestModel:
    def __init__(self, condition_test_panel: 'ConditionTestPanel', tests: List['ConditionTester']):
        self.condition_test_panel = condition_test_panel
        self.tests = list(tests)
        self.map = {test: {'result': None} for test in tests}
        self.completed_test_count = 0
        self.error_count = 0
        self.warning_count = 0
        self.skipped_count = 0

    def run_tests(self, monitor):
        if self.condition_test_runner is not None:
            return
        for test in self.tests:
            self.map[test]['result'] = None
        self.completed_test_count = 0
        self.error_count = 0
        self.warning_count = 0
        self.skipped_count = 0
        self.update_panel()
        self.condition_test_runner = threading.Thread(target=self.run_tests_thread, args=(monitor,))
        self.condition_test_runner.start()

    def skip_tests(self):
        if self.condition_test_runner is not None:
            return
        for test in self.tests:
            self.map[test]['result'] = {'status': 'Skipped'}
        self.completed_test_count = len(self.tests)
        self.error_count = 0
        self.warning_count = 0
        self.skipped_count = len(self.tests)
        self.notify_tests_completed()

    def get_test_count(self):
        return len(self.tests)

    def get_completed_test_count(self):
        return self.completed_test_count

    def get_warning_count(self):
        return self.warning_count

    def get_error_count(self):
        return self.error_count

    def get_skipped_count(self):
        return self.skipped_count

    def condition_test_completed(self):
        self.condition_test_runner = None
        self.notify_tests_completed()

    def starting_test(self, test: 'ConditionTester'):
        self.in_progress_test = test
        self.update_panel()

    def ending_test(self, test: 'ConditionTester', result: Any):
        self.in_progress_test = None
        state = self.map[test]
        status = result['status']
        if status == 'Error':
            self.error_count += 1
        elif status in ['Warning', 'Cancelled']:
            self.warning_count += 1
        else:
            self.skipped_count += 1
        self.completed_test_count += 1
        self.update_panel()

    def skipping_test(self, test: 'ConditionTester'):
        result = {'status': 'Skipped'}
        self.ending_test(test, result)

    def notify_tests_completed(self):
        threading.Thread(target=self.condition_test_panel.tests_completed).start()

    def update_panel(self):
        threading.Thread(target=self.condition_test_panel.update).start()

    @property
    def tests(self) -> List['ConditionTester']:
        return list(self._tests)

    def get_status(self, test: 'ConditionTester') -> Any:
        state = self.map[test]
        return state.get('status', None)

    def is_in_progress(self) -> bool:
        return self.condition_test_runner is not None

    def set_enabled(self, test: 'ConditionTester', enabled: bool):
        state = self.map[test]
        state['enabled'] = enabled
```

Note that the `ConditionTestRunner` class has been modified to use Python's threading module instead of Java's.