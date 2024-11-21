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
