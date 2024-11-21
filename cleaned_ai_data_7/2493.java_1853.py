class DBTraceSnapshot:
    TABLE_NAME = "Snapshots"
    REAL_TIME_COLUMN_NAME = "RealTime"
    SCHEDULE_COLUMN_NAME = "Schedule"
    DESCRIPTION_COLUMN_NAME = "Description"
    THREAD_COLUMN_NAME = "Thread"

    def __init__(self, manager):
        self.manager = manager
        self.real_time = 0
        self.schedule_str = ""
        self.description = ""
        self.thread_key = -1

    @property
    def real_time(self):
        return self._real_time

    @real_time.setter
    def real_time(self, value):
        if hasattr(self, "_real_time"):
            del self._real_time
        self._real_time = value

    @property
    def schedule_str(self):
        return self._schedule_str

    @schedule_str.setter
    def schedule_str(self, value):
        if hasattr(self, "_schedule_str"):
            del self._schedule_str
        self._schedule_str = value

    @property
    def description(self):
        return self._description

    @description.setter
    def description(self, value):
        if hasattr(self, "_description"):
            del self._description
        self._description = value

    @property
    def thread_key(self):
        return self._thread_key

    @thread_key.setter
    def thread_key(self, value):
        if hasattr(self, "_thread_key"):
            del self._thread_key
        self._thread_key = value

    def fresh(self, created=False):
        if created:
            self.thread_key = -1
            self.schedule_str = ""
        else:
            event_thread = self.manager.thread_manager.get_thread(self.thread_key)
            if not self.schedule_str == "":
                try:
                    schedule = TraceSchedule.parse(self.schedule_str)
                except Exception as e:
                    print(f"Could not parse schedule: {self.schedule_str}, error: {e}")
            return

    def __str__(self):
        return f"<DBTraceSnapshot key={self.thread_key}, real_time={self.real_time}, schedule='{self.schedule_str}', description='{self.description}'>"

    def set(self, real_time, description):
        self.real_time = real_time
        self.description = description
        self.update()

    @property
    def trace(self):
        return self.manager.trace

    @trace.setter
    def trace(self, value):
        if hasattr(self, "_manager"):
            del self._manager
        self._manager = value

    @property
    def real_time_millis(self):
        return self.real_time

    @real_time_millis.setter
    def real_time_millis(self, millis):
        try:
            with LockHold.lock(self.manager.lock.write_lock()):
                self.real_time = millis
                self.update()
        except Exception as e:
            print(f"Error updating snapshot: {e}")
        finally:
            if hasattr(self, "_manager"):
                del self._manager

    @property
    def description_str(self):
        return self.description

    @description_str.setter
    def description_str(self, value):
        try:
            with LockHold.lock(self.manager.lock.write_lock()):
                self.description = value
                self.update()
        except Exception as e:
            print(f"Error updating snapshot: {e}")
        finally:
            if hasattr(self, "_manager"):
                del self._manager

    @property
    def event_thread(self):
        return self.event_thread_

    @event_thread.setter
    def event_thread(self, value):
        try:
            with LockHold.lock(self.manager.lock.write_lock()):
                if not value:
                    self.thread_key = -1
                    self.event_thread_ = None
                else:
                    thread = self.manager.thread_manager.assert_is_mine(value)
                    self.thread_key = thread.key()
                    self.event_thread_ = thread
        except Exception as e:
            print(f"Error updating snapshot: {e}")
        finally:
            if hasattr(self, "_manager"):
                del self._manager

    @property
    def schedule_str_(self):
        return self.schedule_str_

    @schedule_str_.setter
    def schedule_str_(self, value):
        try:
            with LockHold.lock(self.manager.lock.write_lock()):
                if not value:
                    self.schedule_ = None
                    self.schedule_str_ = ""
                else:
                    schedule = TraceSchedule.parse(value)
                    self.schedule_ = schedule
                    self.schedule_str_ = str(schedule)
        except Exception as e:
            print(f"Error updating snapshot: {e}")
        finally:
            if hasattr(self, "_manager"):
                del self._manager

    def delete(self):
        self.manager.delete_snapshot(self)

class LockHold:
    @staticmethod
    def lock(lock):
        return lock.write_lock()

class TraceSchedule:
    @classmethod
    def parse(cls, schedule_str):
        # implement parsing logic here
        pass

if __name__ == "__main__":
    manager = DBTraceTimeManager()
    snapshot = DBTraceSnapshot(manager)
