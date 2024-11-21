# Licensed under Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

from typing import Iterator, List

class IMergePathSelector(Iterator[List['PartialPath']]):
    """IMergePathSelector select paths to be merged at a time if all paths of a device cannot be merged 
       at the same time."""
    pass
