class DbgStepCommand:
    def __init__(self, manager, id, suffix):
        self.manager = manager
        self.id = id
        self.suffix = suffix
        self.last_command = "tct"

    def handle(self, event, pending):
        if isinstance(event, AbstractDbgCompletedCommandEvent) and pending.get_command() == self:
            return isinstance(event, DbgCommandErrorEvent) or not pending.find_all_of(DbgRunningEvent)
        elif isinstance(event, DbgRunningEvent):
            pending.claim(event)
            return not pending.find_all_of(AbstractDbgCompletedCommandEvent)
        else:
            return False

    def invoke(self):
        cmd = ""
        prefix = "" if self.id is None else "~" + str(self.id) + " "
        control = self.manager.get_control()
        if self.suffix == ExecSuffix.STEP_INSTRUCTION:
            cmd = "t"
            #control.set_execution_status(DebugStatus.STEP_INTO)
        elif self.suffix == ExecSuffix.NEXT_INSTRUCTION:
            cmd = "p"
            #control.set_execution_status(DebugStatus.STEP_OVER)
        elif self.suffix == ExecSuffix.FINISH:
            cmd = "gu"
            #control.set_execution_status(DebugStatus.STEP_BRANCH)
        elif self.suffix == ExecSuffix.EXTENDED:
            cmd = self.get_last_command()
        event_thread = self.manager.get_event_thread()
        if event_thread is not None and str(event_thread.id) == str(self.id):
            control.execute(cmd)
        else:
            if self.manager.is_kernel_mode():
                print("Thread-specific stepping ignored in kernel-mode")
                control.execute(cmd)
            else:
                control.execute(prefix + cmd)

    def get_last_command(self):
        return self.last_command

    def set_last_command(self, last_command):
        self.last_command = last_command
