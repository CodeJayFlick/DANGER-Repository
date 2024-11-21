class GadpModelForDbgengRootAttacherTest:
    def __init__(self):
        pass

    # NB: testListAttachable fails with OTE  - [] not invalidated

    def model_host(self) -> object:
        return GadpDbgengModelHost()
