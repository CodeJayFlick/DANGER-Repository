Here is the translation of the given Java code into Python:

```Python
class AppShippingFailCases:
    def __init__(self):
        self.num_of_retries = 3
        self.retry_duration = 30000
        self.queue_time = 240000
        self.queue_task_time = 60000
        self.payment_time = 120000
        self.message_time = 150000
        self.employee_time = 240000

    def item_unavailable_case(self):
        ps = PaymentService(PaymentDatabase())
        ss = ShippingService(ShippingDatabase(), ItemUnavailableException())
        ms = MessagingService(MessagingDatabase())
        eh = EmployeeHandle(EmployeeDatabase())
        qdb = QueueDatabase()
        c = Commander(eh, ps, ss, ms, qdb, self.num_of_retries, self.retry_duration,
                      self.queue_time, self.queue_task_time, self.payment_time, self.message_time, self.employee_time)
        user = User("Jim", "ABCD")
        order = Order(user, "book", 10.0)
        c.place_order(order)

    def shipping_not_possible_case(self):
        ps = PaymentService(PaymentDatabase())
        ss = ShippingService(ShippingDatabase(), ShippingNotPossibleException())
        ms = MessagingService(MessagingDatabase())
        eh = EmployeeHandle(EmployeeDatabase())
        qdb = QueueDatabase()
        c = Commander(eh, ps, ss, ms, qdb, self.num_of_retries, self.retry_duration,
                      self.queue_time, self.queue_task_time, self.payment_time, self.message_time, self.employee_time)
        user = User("Jim", "ABCD")
        order = Order(user, "book", 10.0)
        c.place_order(order)

    def shipping_database_unavailable_case(self):
        ps = PaymentService(PaymentDatabase())
        ss = ShippingService(ShippingDatabase(), DatabaseUnavailableException(),
                             DatabaseUnavailableException(), DatabaseUnavailableException(),
                             DatabaseUnavailableException(), DatabaseUnavailableException(),
                             DatabaseUnavailableException())
        ms = MessagingService(MessagingDatabase())
        eh = EmployeeHandle(EmployeeDatabase())
        qdb = QueueDatabase()
        c = Commander(eh, ps, ss, ms, qdb, self.num_of_retries, self.retry_duration,
                      self.queue_time, self.queue_task_time, self.payment_time, self.message_time, self.employee_time)
        user = User("Jim", "ABCD")
        order = Order(user, "book", 10.0)
        c.place_order(order)

    def shipping_success_case(self):
        ps = PaymentService(PaymentDatabase(), DatabaseUnavailableException())
        ss = ShippingService(ShippingDatabase(), DatabaseUnavailableException(),
                             DatabaseUnavailableException())
        ms = MessagingService(MessagingDatabase(), DatabaseUnavailableException())
        eh = EmployeeHandle(EmployeeDatabase())
        qdb = QueueDatabase()
        c = Commander(eh, ps, ss, ms, qdb, self.num_of_retries, self.retry_duration,
                      self.queue_time, self.queue_task_time, self.payment_time, self.message_time, self.employee_time)
        user = User("Jim", "ABCD")
        order = Order(user, "book", 10.0)
        c.place_order(order)

    def main(self):
        asfc = AppShippingFailCases()
        #asfc.item_unavailable_case()
        #asfc.shipping_not_possible_case()
        #asfc.shipping_database_unavailable_case()
        asfc.shipping_success_case()

if __name__ == "__main__":
    app_shipping_fail_cases = AppShippingFailCases()
    app_shipping_fail_cases.main()
```

Please note that this is a direct translation of the given Java code into Python. The original Java code seems to be part of some larger system, and without more context it's difficult to provide meaningful comments or explanations for each section of the code.