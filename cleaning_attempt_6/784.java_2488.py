from abc import ABC, abstractmethod


class DbgModelTargetSessionContainer(ABC):
    @abstractmethod
    def session_added(self, session: object, cause: str) -> None:
        pass

    @abstractmethod
    def session_removed(self, sessionId: int, cause: str) -> None:
        pass

    @abstractmethod
    def get_target_session(self, session: object) -> object:
        pass


class DbgModelTargetSessionContainerImpl(DbgModelTargetSessionContainer):
    def __init__(self):
        self.target_sessions = {}

    def session_added(self, session: object, cause: str) -> None:
        # refresh()
        pass

    def session_removed(self, sessionId: int, cause: str) -> None:
        pass

    def get_target_session(self, session: object) -> object:
        return self.target_sessions.get(session)
