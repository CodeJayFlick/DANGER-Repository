class DbgOpenDumpCommand:
    def __init__(self, manager, args):
        self.manager = manager
        self.args = args
        self.completed = False
        self.created = None

    def handle(self, event, pending):
        if isinstance(event, AbstractDbgCompletedCommandEvent) and pending.get_command() == self:
            self.completed = True
        elif isinstance(event, DbgProcessCreatedEvent):
            self.created = event
        return self.completed and (self.created is not None)

    def complete(self, pending):
        info = self.created.info()
        tinfo = info.initial_thread_info
        so = self.manager.system_objects
        tid = so.get_thread_id_by_handle(tinfo.handle)
        return self.manager.thread(tid)

    def invoke(self):
        dbgeng = self.manager.client
        f = self.args["TraceOrDump"]
        if f.startswith("/"):
            f = f[1:]
        f = f.replace("/", "\\")
        dbgeng.open_dump_file_wide(f)
        self.manager.wait_for_event_ex()
