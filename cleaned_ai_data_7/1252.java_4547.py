class InVmModelForDbgmodelScenarioStackTest:
    def model_host(self):
        return InVmDbgmodelModelHost()

    def post_launch(self, process):
        pass

    def validate_frame_pc(self, index, pc):
        pass


class InVmDbgmodelModelHost:
    pass
