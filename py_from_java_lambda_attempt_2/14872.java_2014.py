Here is the translation of the given Java code into Python:

```Python
class SagaOrchestratorTest:
    def test_execute(self):
        saga_orchestrator = SagaOrchestrator(new_saga(), service_discovery())
        bad_order_result = saga_orchestrator.execute("bad_order")
        crashed_order_result = saga_orchestrator.execute("crashed_order")

        self.assertEqual(Saga.Result.ROLLBACK, bad_order_result)
        self.assertEqual(Saga.Result.CRASHED, crashed_order_result)

    def new_saga(self):
        return Saga.create() \
            .chapter("init an order") \
            .chapter("booking a Fly") \
            .chapter("booking a Hotel") \
            .chapter("withdrawing Money")

    def service_discovery(self):
        return ServiceDiscoveryService() \
            .discover(OrderService()) \
            .discover(FlyBookingService()) \
            .discover(HotelBookingService()) \
            .discover(WithdrawMoneyService())

class Saga:
    @staticmethod
    def create():
        pass

    Result = "ROLLBACK"
    Result += ", CRASHED"

class ServiceDiscoveryService:
    def discover(self, service):
        return self

class OrderService:
    pass

class FlyBookingService:
    pass

class HotelBookingService:
    pass

class WithdrawMoneyService:
    pass
```

Please note that Python does not have direct equivalent of Java's `@Test` annotation. The test method is simply defined as a regular function in the class. Also, Python's `assertEqual` function from the unittest module is used for assertions instead of JUnit's `assertEquals`.