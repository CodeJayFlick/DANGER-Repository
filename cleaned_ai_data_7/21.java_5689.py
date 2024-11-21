# Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

class AbstractDebuggerPlugin:
    def __init__(self):
        pass

    @property
    def auto_service_wiring(self):
        return None  # equivalent to private AutoService.Wiring in Java

    def init(self):
        self.auto_service_wiring = None  # equivalent to super.init() and autoServiceWiring = AutoService.wireServicesProvidedAndConsumed(this) in Java


# No direct translation of the package declaration, as Python does not have a concept similar to packages
