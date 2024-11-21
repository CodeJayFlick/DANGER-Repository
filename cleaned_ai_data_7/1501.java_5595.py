import abc

class SshJoinGdbModelHost(abc.ABC):
    def getModelFactory(self) -> dict:
        return {"SSH username": input("Enter SSH username:"),
                "Use existing session via new-ui": True}

    def getFactoryOptions(self) -> dict:
        try:
            return self.getModelFactory()
        except Exception as e:
            raise AssertionError("Cancelled", e)
