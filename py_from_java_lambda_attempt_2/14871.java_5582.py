Here is the translation of the given Java code into equivalent Python:

```Python
class SagaOrchestratorInternallyTest:
    def __init__(self):
        self.records = []

    @staticmethod
    def new_saga():
        return {
            "1": {"chapter": 1},
            "2": {"chapter": 2},
            "3": {"chapter": 3},
            "4": {"chapter": 4}
        }

    @staticmethod
    def service_discovery():
        services = [
            Service("Service1", lambda x: "+1"),
            Service("Service2", lambda x: "+2"),
            Service("Service3", lambda x: "+3"),
            Service("Service4", lambda x: "+4")
        ]
        return [service.discover() for service in services]

    def execute_test(self):
        saga_orchestrator = SagaOrchestrator(
            self.new_saga(), 
            self.service_discovery()
        )
        result = saga_orchestrator.execute(1)
        assert result == "ROLLBACK"
        assert self.records == ["+1", "+2", "+3", "+4", "-4", "-3", "-2", "-1"]


class Service:
    def __init__(self, name, process):
        self.name = name
        self.process = process

    @property
    def get_name(self):
        return self.name

    def discover(self):
        records.append(f"+{self.get_name}")
        if self.process(4) == "failure":
            records.append("-4")
            return {"result": "ROLLBACK"}
        else:
            records.append("-" + self.get_name)
            return {"result": "success"}

# Usage
test = SagaOrchestratorInternallyTest()
test.execute_test()

```

This Python code does not exactly translate the given Java code, but it should provide a similar functionality.