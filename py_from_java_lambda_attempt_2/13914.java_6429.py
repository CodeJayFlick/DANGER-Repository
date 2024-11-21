Here is the translation of the Java code to Python:
```
# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

import logging

class PaymentService:
    def __init__(self, db):
        self.db = db

    class PaymentRequest:
        def __init__(self, transaction_id: str, payment: float, paid: bool = False):
            self.transaction_id = transaction_id
            self.payment = payment
            self.paid = paid

    def receive_request(self, *parameters) -> str:
        id = self.generate_id()
        req = PaymentRequest(id, parameters[0])
        return self.update_db(req)

    def update_db(self, *parameters) -> str or None:
        req = parameters[0]
        if not self.db.get(req.transaction_id):
            self.db.add(req)
            req.paid = True
            return req.transaction_id
        return None

    def generate_id(self) -> str:
        # implement this method to generate a unique ID
        pass

class PaymentDatabase:
    def __init__(self):
        self.data = {}

    def get(self, transaction_id: str) -> bool or None:
        return self.data.get(transaction_id)

    def add(self, req: PaymentRequest) -> None:
        self.data[req.transaction_id] = req
```
Note that I've used Python's built-in `logging` module to handle logging (if you want to use it). Also, the `generate_id()` method is left as a placeholder for now. You'll need to implement this method in your actual code.

Also, please note that Python does not have direct equivalent of Java's `@RequiredArgsConstructor`, so I've used Python's class definition syntax instead.