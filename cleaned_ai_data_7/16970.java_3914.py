# Licensed under Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

from typing import Callable, Any

class IFileQueryMemMeasurement:
    """Estimate how much memory a file may occupy when being queried during merge."""
    
    def __call__(self, resource: 'TsFileResource') -> int:
        raise NotImplementedError
