class DbgModelTargetSessionImpl:
    def __init__(self, sessions: 'DbgModelTargetSessionContainer', session):
        self.sessions = sessions
        self.session = session
        super().__init__(sessions.model, sessions, f"{session.id}", "Session")
        self.model.add_model_object(session, self)

        self.attributes = DbgModelTargetSessionAttributesImpl(self)
        self.processes = DbgModelTargetProcessContainerImpl(self)

        change_attributes([], [self.attributes, self.processes], {"ACCESSIBLE_ATTRIBUTE_NAME": True,
                                                                  "PROMPT_ATTRIBUTE_NAME": "kd",
                                                                  "STATE_ATTRIBUTE_NAME": "ALIVE"}, "Initialized")

    def set_active(self):
        # manager = self.sessions.manager
        # process = manager.current_process()
        return CompletableFuture.completed_future(None)

    @property
    def accessible(self):
        pass

    @property
    def processes(self):
        return self.processes

class DbgModelTargetProcessContainerImpl:
    def __init__(self, session: 'DbgModelTargetSession'):
        self.session = session

class DbgModelTargetSessionAttributesImpl:
    def __init__(self, session: 'DbgModelTargetSession'):
        self.session = session
