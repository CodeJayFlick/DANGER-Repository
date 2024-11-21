# Licensed under Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

class ShowTriggersOperator:
    def __init__(self, token_int_type):
        pass  # equivalent to super().__init__()

    def generate_physical_plan(self, generator) -> None:
        return ShowTriggersPlan()
