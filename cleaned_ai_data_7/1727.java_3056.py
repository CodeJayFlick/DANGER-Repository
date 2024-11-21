class LldbModelTargetSession:
    def __init__(self):
        self.debug = None  # type: LldbModelTargetDebugContainer
        self.attributes = None  # type: LlldbModelTargetSessionAttributesImpl
        self.processes = None  # type: LlbModelTargetProcessContainer
        self.modules = None  # type: LldModelTargetModuleContainer

    def index_session(self, session):
        return DebugClient.get_id(session)

    def key_session(self, session):
        return PathUtils.make_key(index_session(session))

    @property
    def debugger(self):
        return "kd"  # Used by LldbModelTargetEnvironment

    def __init__(self, sessions: 'LlldbModelTargetSessionContainer', session: object) -> None:
        super().__init__()
        self.debug = LldModelTargetDebugContainerImpl(self)
        self.attributes = LldModelTargetSessionAttributesImpl(self)
        self.processes = LldModelTargetProcessContainerImpl(self)
        self.modules = LldModelTargetModuleContainerImpl(self)

    def change_attributes(self, *args):
        pass  # Not implemented in Python

    @property
    def description(self) -> str:
        return "Initialized"

    async def set_active(self) -> None:
        await get_manager().set_active_session(get_session())

    @property
    def accessible(self) -> bool:
        return True  # Default value, not specified in Java code

    def get_processes(self):
        return self.processes

    def get_modules(self):
        return self.modules

    def get_session(self):
        return None  # Not implemented in Python

    async def resume(self) -> None:
        current_process = await get_manager().get_current_process()
        await model.gate_future(get_manager().execute(LldbContinueCommand(get_manager(), current_process)))

class LldModelTargetDebugContainerImpl:
    pass  # Not implemented in Python

class LddModelTargetSessionAttributesImpl:
    pass  # Not implemented in Python

class LldModelTargetProcessContainerImpl:
    pass  # Not implemented in Python

class LldModelTargetModuleContainerImpl:
    pass  # Not implemented in Python
