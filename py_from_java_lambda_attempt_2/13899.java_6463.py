Here is the translation of the given Java code into Python:

```Python
class AppQueueFailCases:
    def __init__(self):
        self.num_of_retries = 3
        self.retry_duration = 30000
        self.queue_time = 240000
        self.queue_task_time = 60000
        self.payment_time = 120000
        self.message_time = 150000
        self.employee_time = 240000

    def queue_payment_task_database_unavailable_case(self):
        ps = PaymentService(PaymentDatabase(), DatabaseUnavailableException(),
                            DatabaseUnavailableException(), DatabaseUnavailableException(),
                            DatabaseUnavailableException(), DatabaseUnavailableException())
        ss = ShippingService(ShippingDatabase())
        ms = MessagingService(MessagingDatabase())
        eh = EmployeeHandle(EmployeeDatabase())
        qdb = QueueDatabase(DatabaseUnavailableException(), DatabaseUnavailableException,
                             DatabaseUnavailableException, DatabaseUnavailableException)
        c = Commander(eh, ps, ss, ms, qdb, self.num_of_retries, self.retry_duration,
                      self.queue_time, self.queue_task_time, self.payment_time, self.message_time, self.employee_time)
        user = User("Jim", "ABCD")
        order = Order(user, "book", 10.0)
        c.place_order(order)

    def queue_message_task_database_unavailable_case(self):
        ps = PaymentService(PaymentDatabase())
        ss = ShippingService(ShippingDatabase())
        ms = MessagingService(MessagingDatabase(), DatabaseUnavailableException(),
                              DatabaseUnavailableException(), DatabaseUnavailableException,
                              DatabaseUnavailableException, DatabaseUnavailableException)
        eh = EmployeeHandle(EmployeeDatabase())
        qdb = QueueDatabase(DatabaseUnavailableException(), DatabaseUnavailableException,
                             DatabaseUnavailableException, DatabaseUnavailableException)
        c = Commander(eh, ps, ss, ms, qdb, self.num_of_retries, self.retry_duration,
                      self.queue_time, self.queue_task_time, self.payment_time, self.message_time, self.employee_time)
        user = User("Jim", "ABCD")
        order = Order(user, "book", 10.0)
        c.place_order(order)

    def queue_employee_db_task_database_unavailable_case(self):
        ps = PaymentService(PaymentDatabase())
        ss = ShippingService(ShippingDatabase(), ItemUnavailableException())
        ms = MessagingService(MessagingDatabase())
        eh = EmployeeHandle(EmployeeDatabase(), DatabaseUnavailableException(),
                            DatabaseUnavailableException, DatabaseUnavailableException,
                            DatabaseUnavailableException, DatabaseUnavailableException)
        qdb = QueueDatabase(DatabaseUnavailableException(), DatabaseUnavailableException,
                             DatabaseUnavailableException, DatabaseUnavailableException)
        c = Commander(eh, ps, ss, ms, qdb, self.num_of_retries, self.retry_duration,
                      self.queue_time, self.queue_task_time, self.payment_time, self.message_time, self.employee_time)
        user = User("Jim", "ABCD")
        order = Order(user, "book", 10.0)
        c.place_order(order)

    def queue_success_case(self):
        ps = PaymentService(PaymentDatabase(), DatabaseUnavailableException(),
                            DatabaseUnavailableException, DatabaseUnavailableException,
                            DatabaseUnavailableException, DatabaseUnavailableException)
        ss = ShippingService(ShippingDatabase())
        ms = MessagingService(MessagingDatabase(), DatabaseUnavailableException(),
                              DatabaseUnavailableException)
        eh = EmployeeHandle(EmployeeDatabase())
        qdb = QueueDatabase(DatabaseUnavailableException(), DatabaseUnavailableException)
        c = Commander(eh, ps, ss, ms, qdb, self.num_of_retries, self.retry_duration,
                      self.queue_time, self.queue_task_time, self.payment_time, self.message_time, self.employee_time)
        user = User("Jim", "ABCD")
        order = Order(user, "book", 10.0)
        c.place_order(order)

    def main(self):
        aqfc = AppQueueFailCases()
        #aqfc.queue_payment_task_database_unavailable_case()
        #aqfc.queue_message_task_database_unavailable_case()
        #aqfc.queue_employee_db_task_database_unavailable_case()
        aqfc.queue_success_case()

if __name__ == "__main__":
    main()
```

Note: Python does not support direct translation of Java code. The above Python code is an equivalent implementation of the given Java code, but it may not be identical in terms of syntax or semantics.