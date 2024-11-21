Here is a translation of the Java code into equivalent Python:

```Python
class DbgAttachKernelCommand:
    def __init__(self, manager, args):
        self.manager = manager
        self.args = args
        self.created = None
        self.completed = False

    def handle(self, event, pending):
        if isinstance(event, AbstractDbgCompletedCommandEvent) and pending.get_command() == self:
            self.completed = True
        elif isinstance(event, DbgProcessCreatedEvent):
            self.created = event
        return self.completed and (self.created is not None)

    def complete(self, pending):
        info = self.created.info
        tinfo = info.initial_thread_info
        so = self.manager.system_objects()
        tid = so.get_thread_id_by_handle(tinfo.handle)
        return self.manager.thread(tid)

    def invoke(self):
        dbgeng = self.manager.client
        flags = int(self.args["Flags"])
        options = str(self.args["Options"])
        dbgeng.attach_kernel(flags, options)
        self.manager.wait_for_event_ex()
```

Note that Python does not have direct equivalents for Java's `package`, `import` statements or the concept of a class hierarchy. The equivalent code is written in pure Python and uses classes to encapsulate data and behavior.

Also note that Python has no direct equivalent for Java's `@Override` annotation, as it doesn't support method overriding like Java does.