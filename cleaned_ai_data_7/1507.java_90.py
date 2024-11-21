import queue
from threading import Thread
from time import sleep


class AbstractClientThreadExecutor:
    def __init__(self):
        self.client = None
        self.shutting_down = False
        self.queue = queue.PriorityQueue()
        self.wait_registered = True

    def init(self):
        pass  # abstract method, must be implemented by subclass

    @property
    def client(self):
        return self.client

    def cancel_wait(self):
        self.wait_registered = False

    def register_wait(self):
        self.wait_registered = True

    def poll_queue(self):
        with self.queue.mutex:
            try:
                return self.queue.get_nowait()
            except queue.Empty:
                return None

    def run(self):
        while not self.shutting_down:
            next_entry = self.poll_queue()
            if next_entry is None or self.shutting_down:
                break
            try:
                # print("Executing: " + str(next_entry))
                next_entry[1].run()  # assuming the command is a callable object
                # print("Done")
            except Exception as e:
                print(f"Task in executor threw: {e}")

        status = self.client.get_execution_status()
        if status.should_wait and status != DebugStatus.NO_DEBUGGEE or self.wait_registered:
            self.wait_registered = False
            self.manager().wait_for_event()

    def shutdown(self):
        self.shutting_down = True

    def shutdown_now(self):
        self.shutting_down = True
        Thread.interrupt()
        left = list(map(lambda x: x[1], iter(self.queue.get_iter())))
        return left

    @property
    def is_shutdown(self):
        return self.shutting_down

    @property
    def is_terminated(self):
        return not self.thread().is_alive()

    def await_termination(self, timeout=0.0):
        try:
            sleep(timeout)
            if not self.thread().is_alive():
                return True
            else:
                raise Exception("Thread did not terminate")
        except KeyboardInterrupt as e:
            print(f"Termination interrupted: {e}")
            return False

    def execute(self, priority, command):
        if self.shutting_down:
            raise RejectedExecutionException("Executor is shutting down")

        try:
            entry = (priority, command)
            with self.queue.mutex:
                self.queue.put(entry)
        except Exception as e:
            print(f"Error executing task: {e}")

    def execute(self, priority, consumer):
        if self.shutting_down:
            raise RejectedExecutionException("Executor is shutting down")

        try:
            entry = (priority, lambda c=self.client: consumer(c))
            with self.queue.mutex:
                self.queue.put(entry)
        except Exception as e:
            print(f"Error executing task: {e}")

    @property
    def manager(self):
        pass  # abstract method, must be implemented by subclass

    @manager.setter
    def set_manager(self, value):
        pass  # abstract method, must be implemented by subclass


class RejectedExecutionException(Exception):
    pass


# Example usage:
if __name__ == "__main__":
    executor = AbstractClientThreadExecutor()
    executor.init()  # implement this in your subclass

    def command1(client):
        print("Command 1 executed")

    def command2(client):
        print("Command 2 executed")

    executor.execute(10, command1)
    executor.execute(5, command2)

    while not executor.is_shutdown:
        pass
