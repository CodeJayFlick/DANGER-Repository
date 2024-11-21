import threading
from queue import Queue

class BackgroundThreadTaskLauncher:
    def __init__(self, task):
        self.task = task

    def run(self, monitor):
        TaskUtilities.add_tracked_task(task, monitor)

        name = f"Task - {task.get_task_title()}"
        pool = GThreadPool()
        executor = pool.get_executor()
        queue = Queue()

        def worker():
            threading.current_thread().name = name
            task.monitored_run(monitor)
        
        t = threading.Thread(target=worker, daemon=True)
        t.start()

class Task:
    def get_task_title(self):
        pass

    def monitored_run(self, monitor):
        pass

def add_tracked_task(task, monitor):
    # This method should be implemented in the original code
    pass

GThreadPool = None  # Replace with your actual GThreadPool implementation
Swing = None  # Replace with your actual Swing implementation
TaskUtilities = None  # Replace with your actual TaskUtilities implementation
