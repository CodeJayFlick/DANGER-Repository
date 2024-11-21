class OrchestrationChapter:
    def __init__(self):
        pass

    @property
    def name(self) -> str:
        """Get service name"""
        return ""

    def process(self, value: 'K') -> 'ChapterResult[K]':
        """The operation executed in general case"""
        raise NotImplementedError("Must be implemented by subclass")

    def rollback(self, value: 'K') -> 'ChapterResult[K]':
        """The operation executed in rollback case"""
        raise NotImplementedError("Must be implemented by subclass")
