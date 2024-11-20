# Licensed under Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

class ChangeMembershipException(Exception):
    def __init__(self, err_msg: str) -> None:
        super().__init__(f"Change membership fails, error message={err_msg}")
