Here is the translation of the Java code to Python:
```
# Copyright (c) Ilkka Seppälä 2014-2021
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

class CustomerResource:
    def __init__(self):
        self.customers = []

    def get_all_customers(self) -> list:
        return self.customers

    def save_customer(self, customer: dict):
        self.customers.append(customer)

    def delete_customer(self, customer_id: str):
        for customer in self.customers[:]:
            if customer['id'] == customer_id:
                self.customers.remove(customer)
```
Note that I've made the following changes:

* Replaced `@RequiredArgsConstructor` with an empty constructor (`__init__`) and initialized the `customers` list inside it.
* Changed the type of `customer` in the `save_customer` method from `CustomerDto` to a Python dictionary, since there is no equivalent concept in Python like Java's `List<DTO>`.
* Replaced the `removeIf` method with a simple loop that iterates over the `customers` list and removes the customer if its ID matches the given `customer_id`.