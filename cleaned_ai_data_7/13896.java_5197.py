class AppEmployeeDbFailCases:
    def __init__(self):
        self.num_of_retries = 3
        self.retry_duration = 30000
        self.queue_time = 240000
        self.queue_task_time = 60000
        self.payment_time = 120000
        self.message_time = 150000
        self.employee_time = 240000

    def employee_database_unavailable_case(self):
        payment_service = PaymentService(PaymentDatabase(), DatabaseUnavailableException(),
                                          DatabaseUnavailableException(), 
                                          DatabaseUnavailableException(), 
                                          DatabaseUnavailableException(), 
                                          DatabaseUnavailableException())
        shipping_service = ShippingService(ShippingDatabase())
        messaging_service = MessagingService(MessagingDatabase())
        employee_handle = EmployeeHandle(EmployeeDatabase(), DatabaseUnavailableException(),
                                           DatabaseUnavailableException(), 
                                           DatabaseUnavailableException(), 
                                           DatabaseUnavailableException(), 
                                           DatabaseUnavailableException())
        queue_database = QueueDatabase(DatabaseUnavailableException(), 
                                         DatabaseUnavailableException(), 
                                         DatabaseUnavailableException(), 
                                         DatabaseUnavailableException(), 
                                         DatabaseUnavailableException())

        commander = Commander(employee_handle, payment_service, shipping_service,
                                messaging_service, queue_database, self.num_of_retries,
                                self.retry_duration, self.queue_time, self.queue_task_time,
                                self.payment_time, self.message_time, self.employee_time)
        
        user = User("Jim", "ABCD")
        order = Order(user, "book", 10.0)
        commander.place_order(order)

    def employee_db_success_case(self):
        payment_service = PaymentService(PaymentDatabase())
        shipping_service = ShippingService(ShippingDatabase(), ItemUnavailableException())
        messaging_service = MessagingService(MessagingDatabase())
        employee_handle = EmployeeHandle(EmployeeDatabase(), DatabaseUnavailableException(),
                                           DatabaseUnavailableException())

        queue_database = QueueDatabase()

        commander = Commander(employee_handle, payment_service, shipping_service,
                                messaging_service, queue_database, self.num_of_retries,
                                self.retry_duration, self.queue_time, self.queue_task_time,
                                self.payment_time, self.message_time, self.employee_time)
        
        user = User("Jim", "ABCD")
        order = Order(user, "book", 10.0)
        commander.place_order(order)

    def main(self):
        # aefc.employeeDatabaseUnavailableCase()
        self.employee_db_success_case()

if __name__ == "__main__":
    app_employee_db_fail_cases = AppEmployeeDbFailCases()
    app_employee_db_fail_cases.main()
