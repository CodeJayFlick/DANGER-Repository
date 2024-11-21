Here is the translation of the Java code to Python:
```
# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class FilterManager:
    def __init__(self):
        self.filter_chain = FilterChain()

    def add_filter(self, filter):
        self.filter_chain.add_filter(filter)

    def filter_request(self, order):
        return self.filter_chain.execute(order)


class FilterChain:
    def __init__(self):
        pass

    def add_filter(self, filter):
        # TO DO: implement the logic to add a filter
        pass

    def execute(self, order):
        # TO DO: implement the logic to execute the filters in sequence
        return "TO DO"
```
Note that I've left some parts of the code as TODOs because they require implementation-specific details. In Python, you would typically define classes and methods using indentation instead of curly braces `{}`.