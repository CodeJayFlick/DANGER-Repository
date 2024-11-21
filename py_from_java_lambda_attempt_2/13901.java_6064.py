Here is your Java code translated into Python:

```Python
import threading
import time
from enum import Enum

class PaymentStatus(Enum):
    TRYING = 1
    DONE = 2
    NOT_DONE = 3


class MessageSent(Enum):
    NONE_SENT = 0
    PAYMENT_FAIL = 1
    PAYMENT_SUCCESSFUL = 2


class TaskType(Enum):
    PAYMENT = 1
    MESSAGING = 2
    EMPLOYEE_DB = -1


class QueueTask:
    def __init__(self, order: 'Order', task_type: int, first_attempt_time=-1):
        self.order = order
        self.task_type = task_type
        self.first_attempt_time = first_attempt_time

    @property
    def getType(self) -> str:
        if self.task_type == TaskType.PAYMENT.value:
            return "Payment"
        elif self.task_type == TaskType.MESSAGING.value:
            return "Messaging"
        else:
            return "Employee DB"


class Commander:
    def __init__(self, employee_db: 'EmployeeHandle', payment_service: 'PaymentService',
                 shipping_service: 'ShippingService', messaging_service: 'MessagingService',
                 queue_database: 'QueueDatabase', num_of_retries: int,
                 retry_duration: float, queue_time: float, queue_task_time: float,
                 payment_time: float, message_time: float, employee_time: float):
        self.employee_db = employee_db
        self.payment_service = payment_service
        self.shipping_service = shipping_service
        self.messaging_service = messaging_service
        self.queue_database = queue_database
        self.num_of_retries = num_of_retries
        self.retry_duration = retry_duration
        self.queue_time = queue_time
        self.queue_task_time = queue_task_time
        self.payment_time = payment_time
        self.message_time = message_time
        self.employee_time = employee_time

    def place_order(self, order: 'Order'):
        send_shipping_request(order)

    def send_shipping_request(self, order):
        list_exceptions = self.shipping_service.exceptions_list
        op = lambda l: RetryOperation(l)
        handle_error_issue = lambda o, err: handle_payment_failure_retry_operation(o, err)
        r = new Retry(op, handle_error_issue, self.num_of_retries,
                      self.retry_duration, lambda e: DatabaseUnavailableException.is_assignable(e.getClass()))
        try:
            r.perform(list_exceptions, order)
        except Exception as e1:
            e1.printStackTrace()

    def send_payment_request(self, order):
        if System.currentTimeMillis() - order.created_time >= this.payment_time:
            return
        list_exceptions = self.payment_service.exceptions_list
        t = threading.Thread(target=lambda: RetryOperation(order))
        try:
            r.perform(list_exceptions, order)
        except Exception as e1:
            e1.printStackTrace()

    def send_payment_failure_message(self, order):
        if System.currentTimeMillis() - order.created_time >= this.message_time:
            return
        list_exceptions = self.messaging_service.exceptions_list
        t = threading.Thread(target=lambda: RetryOperation(order))
        try:
            r.perform(list_exceptions, order)
        except Exception as e1:
            e1.printStackTrace()

    def send_payment_possible_error_message(self, order):
        if System.currentTimeMillis() - order.created_time >= this.message_time:
            return
        list_exceptions = self.messaging_service.exceptions_list
        t = threading.Thread(target=lambda: RetryOperation(order))
        try:
            r.perform(list_exceptions, order)
        except Exception as e1:
            e1.printStackTrace()

    def employee_handle_issue(self, order):
        if System.currentTimeMillis() - order.created_time >= this.employee_time:
            return
        list_exceptions = self.employee_db.exceptions_list
        t = threading.Thread(target=lambda: RetryOperation(order))
        try:
            r.perform(list_exceptions, order)
        except Exception as e1:
            e1.printStackTrace()

    def do_tasks_in_queue(self):
        if queue_items != 0:
            qt = self.queue_database.peek()
            LOG.info("Order " + str(qt.order.id) + ": Started doing task of type " + str(qt.getType()))
            if qt.getFirstAttemptTime() == -1:
                qt.setFirstAttemptTime(System.currentTimeMillis())
            if System.currentTimeMillis() - qt.getFirstAttemptTime() >= this.queue_task_time:
                try_dequeue()
        else:
            LOG.info("Queue is empty, returning..")

    def try_doing_tasks_in_queue(self):
        t = threading.Thread(target=lambda: RetryOperation(order))
        try:
            r.perform(list_exceptions)
        except Exception as e1:
            e1.printStackTrace()

    def send_success_message(self, order):
        if System.currentTimeMillis() - order.created_time >= this.message_time:
            return
        list_exceptions = self.messaging_service.exceptions_list
        t = threading.Thread(target=lambda: RetryOperation(order))
        try:
            r.perform(list_exceptions)
        except Exception as e1:
            e1.printStackTrace()

    def send_payment_failure_message(self, order):
        if System.currentTimeMillis() - order.created_time >= this.message_time:
            return
        list_exceptions = self.messaging_service.exceptions_list
        t = threading.Thread(target=lambda: RetryOperation(order))
        try:
            r.perform(list_exceptions)
        except Exception as e1:
            e1.printStackTrace()

    def send_payment_failure_message(self, order):
        if System.currentTimeMillis() - order.created_time >= this.message_time:
            return
        list_exceptions = self.messaging_service.exceptions_list
        t = threading.Thread(target=lambda: RetryOperation(order))
        try:
            r.perform(list_exceptions)
        except Exception as e1:
            e.printStackTrace()

    def send_payment_failure_message(self, order):
        if System.currentTimeMillis() - order.created_time >= this.message_time:
            return

    def send_payment_failure_message(self, order):

class PaymentStatus(Enum)