Here is a translation of the Java code into equivalent Python:

```Python
class JdiModelTargetObjectReference:
    def __init__(self, object, objref, is_element):
        self.objref = objref
        super().__init__(object)

    @property
    def reference_type(self):
        return self._reference_type

    @reference_type.setter
    def reference_type(self, value):
        self._reference_type = value

    @property
    def owner(self):
        return self._owner

    @owner.setter
    def owner(self, value):
        if isinstance(value, JdiModelTargetThread):
            self._owner = value
        else:
            raise ValueError("Owner must be an instance of JdiModelTargetThread")

    def request_attributes(self, refresh=False):
        try:
            owning_thread = objref.owning_thread()
            if owning_thread is not None:
                owner = getInstance(owning_thread)
                self.owner = owner
                change_attributes({"Owner": owner}, "Initialized")
            waiting_threads = objref.waiting_threads()
            if waiting_threads is not None:
                target_waiting_threads = JdiModelTargetThreadContainer(self, "Waiting Threads", waiting_threads)
                change_attributes({target_waiting_threads: }, Map.(), "Initialized")

        except IncompatibleThreadStateException as e:
            # Ignore
            pass

    def init(self):
        return CompletableFuture.completedFuture(None)

    @property
    def display(self):
        if self.objref is None:
            return super().display()
        else:
            return str(self.objref)
```

Please note that Python does not have direct equivalent of Java's `CompletableFuture` and some other classes. Also, this translation assumes that the necessary imports are made at the top of your Python file.