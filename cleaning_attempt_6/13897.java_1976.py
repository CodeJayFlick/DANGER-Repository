class AppMessagingFailCases:
    def __init__(self):
        self.num_of_retries = 3
        self.retry_duration = 30000
        self.queue_time = 240000
        self.queue_task_time = 60000
        self.payment_time = 120000
        self.message_time = 150000
        self.employee_time = 240000

    def messaging_database_unavailable_case_payment_success(self):
        ps = PaymentService(PaymentDatabase())
        ss = ShippingService(ShippingDatabase())
        ms = MessagingService(MessagingDatabase(), DatabaseUnavailableException(),
                               DatabaseUnavailableException(), 
                               DatabaseUnavailableException(), 
                               DatabaseUnavailableException(), 
                               DatabaseUnavailableException(), 
                               DatabaseUnavailableException())
        eh = EmployeeHandle(EmployeeDatabase())
        qdb = QueueDatabase()
        c = Commander(eh, ps, ss, ms, qdb, self.num_of_retries, self.retry_duration,
                      self.queue_time, self.queue_task_time, self.payment_time, self.message_time, 
                      self.employee_time)
        user = User("Jim", "ABCD")
        order = Order(user, "book", 10.0)
        c.place_order(order)

    def messaging_database_unavailable_case_payment_error(self):
        ps = PaymentService(PaymentDatabase(), DatabaseUnavailableException(),
                            DatabaseUnavailableException(), 
                            DatabaseUnavailableException(), 
                            DatabaseUnavailableException(), 
                            DatabaseUnavailableException())
        ss = ShippingService(ShippingDatabase())
        ms = MessagingService(MessagingDatabase(), DatabaseUnavailableException(),
                               DatabaseUnavailableException(), 
                               DatabaseUnavailableException(), 
                               DatabaseUnavailableException(), 
                               DatabaseUnavailableException(), 
                               DatabaseUnavailableException(), 
                               DatabaseUnavailableException(), 
                               DatabaseUnavailableException(), 
                               DatabaseUnavailableException(), 
                               DatabaseUnavailableException())
        eh = EmployeeHandle(EmployeeDatabase())
        qdb = QueueDatabase()
        c = Commander(eh, ps, ss, ms, qdb, self.num_of_retries, self.retry_duration,
                      self.queue_time, self.queue_task_time, self.payment_time, self.message_time, 
                      self.employee_time)
        user = User("Jim", "ABCD")
        order = Order(user, "book", 10.0)
        c.place_order(order)

    def messaging_database_unavailable_case_payment_failure(self):
        ps = PaymentService(PaymentDatabase(), DatabaseUnavailableException(),
                            DatabaseUnavailableException(), 
                            DatabaseUnavailableException(), 
                            DatabaseUnavailableException(), 
                            DatabaseUnavailableException())
        ss = ShippingService(ShippingDatabase())
        ms = MessagingService(MessagingDatabase(), DatabaseUnavailableException(),
                               DatabaseUnavailableException())
        eh = EmployeeHandle(EmployeeDatabase())
        qdb = QueueDatabase(DatabaseUnavailableException(), DatabaseUnavailableException(),
                             DatabaseUnavailableException(), DatabaseUnavailableException(),
                             DatabaseUnavailableException(), DatabaseUnavailableException())
        c = Commander(eh, ps, ss, ms, qdb, self.num_of_retries, self.retry_duration,
                      self.queue_time, self.queue_task_time, self.payment_time, self.message_time, 
                      self.employee_time)
        user = User("Jim", "ABCD")
        order = Order(user, "book", 10.0)
        c.place_order(order)

    def messaging_success_case(self):
        ps = PaymentService(PaymentDatabase(), DatabaseUnavailableException(),
                            DatabaseUnavailableException(), 
                            DatabaseUnavailableException(), 
                            DatabaseUnavailableException(), 
                            DatabaseUnavailableException())
        ss = ShippingService(ShippingDatabase())
        ms = MessagingService(MessagingDatabase(), DatabaseUnavailableException(),
                               DatabaseUnavailableException())
        eh = EmployeeHandle(EmployeeDatabase())
        qdb = QueueDatabase()
        c = Commander(eh, ps, ss, ms, qdb, self.num_of_retries, self.retry_duration,
                      self.queue_time, self.queue_task_time, self.payment_time, self.message_time, 
                      self.employee_time)
        user = User("Jim", "ABCD")
        order = Order(user, "book", 10.0)
        c.place_order(order)

    @staticmethod
    def main(args):
        amfc = AppMessagingFailCases()
        #amfc.messaging_database_unavailable_case_payment_success()
        #amfc.messaging_database_unavailable_case_payment_error() 
        #amfc.messaging_database_unavailable_case_payment_failure() 
        amfc.messaging_success_case()

if __name__ == "__main__":
    AppMessagingFailCases.main([])
