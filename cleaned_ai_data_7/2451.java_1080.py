class DBTraceStackFrame:
    TABLE_NAME = "StackFrames"
    STACK_COLUMN_NAME = "Stack"
    LEVEL_COLUMN_NAME = "Level"
    PC_COLUMN_NAME = "PC"
    COMMENT_COLUMN_NAME = "Comment"

    def __init__(self, manager: 'DBTraceStackManager', store, record):
        super().__init__(store, record)
        self.manager = manager
        self.stack_key = None
        self.level = 0
        self.pc = None
        self.comment = ""

    @property
    def overlay_space_adapter(self) -> 'DBTraceOverlaySpaceAdapter':
        return self.manager.overlay_adapter

    def fresh(self):
        if not hasattr(self, "stack"):
            stack = self.manager.get_stack_by_key(self.stack_key)
            setattr(self, "stack", stack)

    @classmethod
    def get_table_name(cls):
        return cls.TABLE_NAME

    def set_stack(self, stack: 'DBTraceStack'):
        self.stack = stack
        self.stack_key = stack.key
        self.update_stack_column()

    @property
    def stack(self) -> 'DBTraceStack':
        return getattr(self, "stack")

    @property
    def level(self):
        return getattr(self, "level", 0)

    @property
    def program_counter(self) -> 'Address':
        return getattr(self, "pc")

    def set_program_counter(self, pc: 'Address'):
        self.manager.assert_valid_address(pc)
        if hasattr(self, "pc") and self.pc == pc:
            return

        try:
            with self.manager.lock.write_lock():
                setattr(self, "pc", pc)
                self.update_pc_column()
        finally:
            self.manager.set_changed(TraceStackChangeType.CHANGED, None, self.stack)

    @property
    def comment(self) -> str:
        return getattr(self, "comment")

    def set_comment(self, comment: str):
        try:
            with self.manager.lock.write_lock():
                setattr(self, "comment", comment)
                self.update_comment_column()
        finally:
            self.manager.set_changed(TraceStackChangeType.CHANGED, None, self.stack)

    @property
    def level(self) -> int:
        return getattr(self, "level")

    def set_level(self, level: int):
        setattr(self, "level", level)
        self.update_level_column()

class DBAnnotatedObjectInfo:
    pass

@DBAnnotatedObjectInfo(version=0)
class DBTraceStackFrame(DBAnnotatedObject):
    # ... same as above ...
