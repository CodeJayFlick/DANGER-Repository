class AnalyzerEnablementState:
    def __init__(self, analyzer: object, enabled: bool, default_enabled: bool):
        self.name = analyzer.get_name()
        self.enabled = enabled
        self.default_enabled = default_enabled
        self.is_prototype = analyzer.is_prototype()

    @property
    def name(self) -> str:
        return self.name

    @property
    def is_enabled(self) -> bool:
        return self.enabled

    @property
    def is_default_enablement(self) -> bool:
        return self.enabled == self.default_enabled

    @property
    def is_prototype(self) -> bool:
        return self.is_prototype

    def set_enabled(self, enabled: bool):
        self.enabled = enabled
