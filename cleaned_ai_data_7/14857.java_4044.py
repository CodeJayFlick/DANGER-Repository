class ChapterResult:
    def __init__(self, value: any, state):
        self.value = value
        self.state = state

    @property
    def value(self) -> any:
        return self.value

    def is_success(self) -> bool:
        return self.state == "SUCCESS"

    @staticmethod
    def success(val: any) -> 'ChapterResult':
        return ChapterResult(val, "SUCCESS")

    @staticmethod
    def failure(val: any) -> 'ChapterResult':
        return ChapterResult(val, "FAILURE")


class State(str):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"

