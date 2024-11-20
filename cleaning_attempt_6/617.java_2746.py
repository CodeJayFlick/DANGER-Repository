class DbgLaunchProcessCommand:
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
        so = self.manager.system_objects
        tid = so.get_thread_id_by_handle(tinfo.handle)
        return self.manager.thread(tid)

    def invoke(self):
        dbgeng = self.manager.client
        new_args = []
        for arg in self.args:
            na = arg
            if arg.startswith('/'):
                na = na[1:]
            na = na.replace('/', '\\')
            new_args.append(na)
        dbgeng.create_process(dbgeng.get_local_server(), ' '.join(new_args), BitmaskSet.of(DebugCreateFlags.DEBUG_PROCESS))
        self.manager.wait_for_event_ex()
