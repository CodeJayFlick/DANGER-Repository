# Copyright 2020 Dremio
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import re

class SinglePageAppRoutingFilter:
    UI_ROUTES = ["/tree"]

    def reroute_ui_paths(self, path):
        if any(path.startswith(prefix) for prefix in self.UI_ROUTES):
            return "/"

    def route(self, path):
        if self.reroute_ui_paths(path):
            return "/"
        else:
            # default routing
            pass

# Example usage:
filter = SinglePageAppRoutingFilter()
print(filter.route("/tree"))  # Output: /
print(filter.route("/other/path"))  # Output: None (default routing)
