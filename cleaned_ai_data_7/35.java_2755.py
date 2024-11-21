# Licensed under Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import ghidra_app_util_exporter_intelhexexporter

class TraceViewIntelHexExporter:
    def can_export_domain_object(self, domain_object_class):
        return issubclass(domain_object_class, ghidra_trace_model.Trace)
