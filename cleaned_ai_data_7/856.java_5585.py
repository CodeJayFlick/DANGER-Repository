class GadpModelForDbgengFrameActivationTest:
    def get_stack_pattern(self):
        return PathPattern("Sessions[0].Processes[].Threads[].Stack[]")

    @property
    def model_host(self) -> 'GadpDbgengModelHost':
        return GadpDbgengModelHost()

class GadpDbgengModelHost:
    pass

# You can use the following code to test your classes if you want.
if __name__ == "__main__":
    instance = GadpModelForDbgengFrameActivationTest()
    print(instance.get_stack_pattern())
