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

class TraceViewAsciiExporter:
    def can_export_domain_object(self, domain_object_class):
        return issubclass(domain_object_class, Trace)

import ghidra.app.util.exporter.ascii_asciiexporter as AsciiExporter

class TraceViewAsciiExporter(AsciiExporter):
    pass
