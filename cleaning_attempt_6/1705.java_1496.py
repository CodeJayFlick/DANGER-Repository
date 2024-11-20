class DebugContainer:
    def __init__(self):
        self.breakpoints = BreakpointContainer()

    @property
    def breakpoints(self):
        return self._breakpoints


class LldbModelTargetDebugContainer(LldbModelTargetObject, DebugContainer):
    def __init__(self, session: 'LldbModelTargetSession'):
        super().__init__(session.model, "Debug", "DebugContainer")
        self.breakpoints = BreakpointContainer(session.session)


class BreakpointContainer:
    pass


# Note that this is a simplified translation and does not include all the Java features.
