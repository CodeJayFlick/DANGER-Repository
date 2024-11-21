class LldbSessionSelectedEvent:
    def __init__(self, session):
        self.id = DebugClient.get_id(session)
        self.session = session

    @property
    def id(self):
        return self._id

    @property
    def session(self):
        return self._session


# Assuming you have a class called DebugClient with the following method:
class DebugClient:
    @staticmethod
    def get_id(session):
        # Your code here to implement this method
        pass
