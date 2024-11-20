class AppPaymentFailCases:
    def __init__(self):
        self.num_of_retries = 3
        self.retry_duration = 30000
        self.queue_time = 240000
        self.queue_task_time = 60000
        self.payment_time = 120000
        self.message_time = 150000
        self.employee_time = 240000

    def payment_not_possible_case(self):
        ps = PaymentService(PaymentDatabase(), DatabaseUnavailableException(),
                            PaymentDetailsErrorException())
        ss = ShippingService(ShippingDatabase())
        ms = MessagingService(MessagingDatabase(), DatabaseUnavailableException())
        eh = EmployeeHandle(EmployeeDatabase())
        qdb = QueueDatabase(DatabaseUnavailableException())
        c = Commander(eh, ps, ss, ms, qdb,
                      self.num_of_retries, self.retry_duration,
                      self.queue_time, self.queue_task_time,
                      self.payment_time, self.message_time, self.employee_time)
        user = User("Jim", "ABCD")
        order = Order(user, "book", 10.0)
        c.place_order(order)

    def payment_database_unavailable_case(self):
        ps = PaymentService(PaymentDatabase(), DatabaseUnavailableException(),
                            DatabaseUnavailableException(), DatabaseUnavailableException(),
                            DatabaseUnavailableException(), DatabaseUnavailableException(),
                            DatabaseUnavailableException())
        ss = ShippingService(ShippingDatabase())
        ms = MessagingService(MessagingDatabase())
        eh = EmployeeHandle(EmployeeDatabase())
        qdb = QueueDatabase()
        c = Commander(eh, ps, ss, ms, qdb,
                      self.num_of_retries, self.retry_duration,
                      self.queue_time, self.queue_task_time,
                      self.payment_time, self.message_time, self.employee_time)
        user = User("Jim", "ABCD")
        order = Order(user, "book", 10.0)
        c.place_order(order)

    def payment_success_case(self):
        ps = PaymentService(PaymentDatabase(), DatabaseUnavailableException(),
                            DatabaseUnavailableException())
        ss = ShippingService(ShippingDatabase())
        ms = MessagingService(MessagingDatabase(), DatabaseUnavailableException())
        eh = EmployeeHandle(EmployeeDatabase())
        qdb = QueueDatabase(DatabaseUnavailableException())
        c = Commander(eh, ps, ss, ms, qdb,
                      self.num_of_retries, self.retry_duration,
                      self.queue_time, self.queue_task_time,
                      self.payment_time, self.message_time, self.employee_time)
        user = User("Jim", "ABCD")
        order = Order(user, "book", 10.0)
        c.place_order(order)

    def main(self):
        apfc = AppPaymentFailCases()
        #apfc.payment_not_possible_case()
        #apfc.payment_database_unavailable_case()
        apfc.payment_success_case()

if __name__ == "__main__":
    app_payment_fail_cases = AppPaymentFailCases()
    app_payment_fail_cases.main()
