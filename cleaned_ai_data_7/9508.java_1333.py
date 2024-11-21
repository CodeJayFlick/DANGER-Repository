import tkinter as tk
from tkinter import scrolledtext
from threading import Thread
from time import sleep

class ConditionTestPanel:
    def __init__(self):
        self.condition_test_model = None
        self.task_monitor = None
        self.test_panel_list = []
        self.test_status_panel_list = []
        self.runs_label = None
        self.errors_label = None
        self.warnings_label = None
        self.overall_progress_bar = None
        self.details_label = None

    def add_listener(self, listener):
        if not hasattr(self, 'listeners'):
            self.listeners = set()
        self.listeners.add(listener)

    def remove_listener(self, listener):
        try:
            self.listeners.remove(listener)
        except KeyError:
            pass  # Listener was already removed or never added

    @property
    def has_run_tests(self):
        return self.condition_test_model.get_completed_test_count() == self.condition_test_model.get_test_count()

    @property
    def is_in_progress(self):
        return self.condition_test_model.is_in_progress()

    @property
    def error_count(self):
        return self.condition_test_model.error_count

    @property
    def warning_count(self):
        return self.condition_test_model.warning_count

    @property
    def skipped_count(self):
        return self.condition_test_model.skipped_count

    def update(self):
        self.update_summary()
        self.update_overall_progress()
        self.update_test_status()

    def select_test(self, test):
        if not hasattr(self, 'selected_test'):
            self.selected_test = None
        for panel in self.test_panel_list:
            panel.set_selected(test)
        self.update_detail_message()

    def tests_completed(self):
        for listener in self.listeners:
            listener.tests_completed()
        self.update()
        best_test_to_select = None
        for test, status in zip(*[self.condition_test_model.get_tests(), [test.status for test in self.test_panel_list]]):
            if status == 'Error':
                best_test_to_select = test
                break  # Find the first error and stop looking
            elif status == 'Warning' and not best_test_to_select:
                best_test_to_select = test
        if best_test_to_select:
            self.select_test(best_test_to_select)

    def cancel(self):
        self.condition_test_model.cancel()

class OverallProgressBar(tk.Frame):
    def __init__(self, master=None):
        super().__init__(master)
        self.max_progress = 0
        self.progress = 0

    def set_max_progress(self, max_progress):
        if max_progress <= 0:
            max_progress = 1
        self.max_progress = max_progress
        self.update()

    def set_progress(self, progress):
        if progress > self.max_progress:
            progress = self.max_progress
        self.progress = progress
        self.update()

class TestPanel(tk.Frame):
    def __init__(self, master=None, test=None):
        super().__init__(master)
        self.test = test
        self.checkbox = tk.BooleanVar()
        self.label = tk.Label(self)

    @property
    def selected(self):
        return self.test == self.parent.selected_test

    def set_selected(self, test):
        if not hasattr(self, 'parent'):
            raise AttributeError('TestPanel must be part of a ConditionTestPanel')
        self.checkbox.set(test == self.parent.selected_test)
        self.label.config(text=str(test.name) + f' ({test.description})')

class TestStatusPanel(tk.Frame):
    def __init__(self, master=None, test=None):
        super().__init__(master)
        self.test = test
        self.label = tk.Label(self)

    @property
    def status(self):
        return 'Error'

    def set_status(self, status):
        if status == 'Error':
            icon = 'ERROR_ICON'
        elif status == 'Warning':
            icon = 'WARNING_ICON'
        else:
            icon = None
        self.label.config(text=str(status), image=icon)

class ConditionTestModel:
    def __init__(self, parent=None, tests=None):
        if not hasattr(self, 'parent'):
            self.parent = parent
        self.tests = tests

    @property
    def error_count(self):
        return 0

    @property
    def warning_count(self):
        return 0

    @property
    def skipped_count(self):
        return 0

    @property
    def get_completed_test_count(self):
        return len([test for test in self.tests if test.result == 'Passed'])

    @property
    def get_test_count(self):
        return len(self.tests)

    def run_tests(self, task_monitor=None):
        # TO DO: implement running tests

    def skip_tests(self):
        for panel in self.parent.test_panel_list:
            panel.checkbox.set(False)
        self.parent.update()

class ConditionTester:
    def __init__(self, name=None, description=None):
        if not hasattr(self, 'name'):
            self.name = None
        if not hasattr(self, 'description'):
            self.description = None

    @property
    def name(self):
        return self._name

    @property
    def description(self):
        return self._description

class TestConditionRun(ConditionTester):
    def __init__(self, name=None, run_iterations=0, result='Passed', msg=''):
        super().__init__(name=name)
        if not hasattr(self, 'run_iterations'):
            self.run_iterations = 0
        if not hasattr(self, '_result'):
            self._result = None
        if not hasattr(self, '_msg'):
            self._msg = ''
        self.name = name
        self.run_iterations = run_iterations
        self.result = result
        self.msg = msg

    def get_description(self):
        return f'{self.name} description goes here'

if __name__ == '__main__':
    root = tk.Tk()
    panel = ConditionTestPanel()
    for test in [TestConditionRun('Beta ConfigTest', 20, 'Error', 'This is an error This is an error This is an error' + 'This is an error This is an error And this is another line'),
                 TestConditionRun('Alpha ConfigTest', 15),
                 TestConditionRun('Gamma adfda asdfasdf ConfigTest', 50),
                 TestConditionRun('Zeta ConfigTest', 30, 'Warning', 'This is a warning'),
                 TestConditionRun('Delta ConfigTest', 20)]:
        test_panel = TestPanel(root, test)
        panel.test_panel_list.append(test_panel)

    root.mainloop()
