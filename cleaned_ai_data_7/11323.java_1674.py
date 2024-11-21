import ghidra_framework_model_project_manager as project_manager

class TestProjectManager(project_manager.DefaultProjectManager):
    _project_manager = None

    @classmethod
    def get(cls):
        if cls._project_manager is None:
            cls._project_manager = TestProjectManager()
        return cls._project_manager

    def __init__(self):
        super().__init__()
