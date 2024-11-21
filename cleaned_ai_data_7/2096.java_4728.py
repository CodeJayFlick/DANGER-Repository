# This part is a license notice, not relevant for this translation.
# It's usually included in every file that uses Apache License.

from typing import TypeVar, Generic

R = TypeVar('R')
T = TypeVar('T')

class AsyncLoopFirstActionProduces(Generic[R, T]):
    def __call__(self, handler: 'AsyncLoopHandlerForFirst[R, T]'):
        pass  # Nothing to do here
