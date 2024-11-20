class TaskUtilities:
    running_tasks = {}
    listeners = []

    def add_tracked_task_listener(self, listener):
        if listener in self.listeners:
            self.listeners.remove(listener)
        self.listeners.append(listener)

    def remove_tracked_task_listener(self, listener):
        try:
            self.listeners.remove(listener)
        except ValueError:
            pass

    def add_tracked_task(self, task, monitor):
        if not SystemUtilities.is_in_testing_mode():
            return
        if task in self.running_tasks:
            return
        self.running_tasks[task] = monitor
        for listener in self.listeners:
            listener.task_added(task)

    def remove_tracked_task(self, task):
        if not SystemUtilities.is_in_testing_mode():
            return
        try:
            del self.running_tasks[task]
        except KeyError:
            pass
        for listener in self.listeners:
            listener.task_removed(task)

    @staticmethod
    def is_executing_tasks():
        if SystemUtilities.is_in_testing_mode():
            return len(TaskUtilities.running_tasks) > 0
        return False

    @staticmethod
    def is_task_running(title):
        if not SystemUtilities.is_in_testing_mode():
            return False
        tasks = list(TaskUtilities.running_tasks.keys())
        for task in tasks:
            if task.get_task_title() == title:
                return True
        return False


class TrackedTaskListener:
    def task_added(self, task):
        pass

    def task_removed(self, task):
        pass


# Usage example:

task_utilities = TaskUtilities()
listener = TrackedTaskListener()

task_utilities.add_tracked_task_listener(listener)

task_utilities.add_tracked_task("some-task", "monitor")
