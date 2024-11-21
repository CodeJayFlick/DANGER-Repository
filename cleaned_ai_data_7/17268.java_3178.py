# Licensed under Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

class ShowContinuousQueriesOperator:
    def __init__(self, token_int_type):
        super().__init__(token_int_type)
        self.operator_type = "SHOW_CONTINUOUS_QUERIES"

ShowContinuousQueriesOperator.__doc__ = """
A class representing the SHOW CONTINUOUS QUERIES operator.
"""

if __name__ == "__main__":
    pass
