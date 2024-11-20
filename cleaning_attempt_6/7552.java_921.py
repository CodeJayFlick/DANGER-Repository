class UngroupAllVertexFunctionGraphJob:
    def __init__(self, controller):
        self.controller = controller
        self.is_finished = False

    def execute(self, listener):
        try:
            self.controller.ungroup_all_vertices()
        finally:
            self.is_finished = True
            listener.job_finished(self)

    def can_shortcut(self):
        return False

    def shortcut(self):
        raise UnsupportedOperationException("Cannot shortct job: " + str(self))

    @property
    def is_finished(self):
        return self._is_finished

    @is_finished.setter
    def is_finished(self, value):
        self._is_finished = value

    def dispose(self):
        self.is_finished = True

    def __str__(self):
        return "Ungroup All Group Vertices Job"
