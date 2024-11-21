class AbstractModelForGdbFactoryTest:
    def get_failing_factory_options(self):
        return {
            "GDB launch command": "/THIS/SHOULD/NEVER/EXIST"
        }
