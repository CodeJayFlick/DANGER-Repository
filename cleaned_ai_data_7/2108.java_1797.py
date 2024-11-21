import asyncio
from typing import TypeVar, Generic, Any

class AsyncSequenceWithTemp(Generic[R, T]):
    def __init__(self, seq_result: 'asyncio.Future[R]', tmp_result: 'asyncio.Future[T]'):
        self.seq_result = seq_result
        self.tmp_result = tmp_result

    async def then(self, action: callable[[R], Any], type_spec: TypeSpec[U]) -> 'AsyncSequenceWithTemp[R, U]':
        return AsyncSequenceWithTemp(
            await asyncio.wait_for(self.tmp_result.then(lambda result: action(result)), None),
            await self.tmp_result.then(lambda result: action(result))
        )

    async def then_with_executor(self, executor: Any, action: callable[[R], Any]) -> 'AsyncSequenceWithTemp[R]':
        return AsyncSequenceWithTemp(
            await asyncio.wait_for(self.tmp_result.then(lambda result: action(result)), None),
            await self.tmp_result.then(lambda result: action(result))
        )

    async def then_with_storer(self, storage: AtomicReference[U]) -> 'AsyncSequenceWithoutTemp[R]':
        return AsyncSequenceWithoutTemp(
            await asyncio.wait_for(self.tmp_result.then(lambda result: action(result)), None),
            await self.tmp_result.then(lambda result: action(result))
        )

    async def on_exit(self, action: callable[[R], Any]) -> 'AsyncSequenceWithTemp[R, T]':
        self.seq_result.add_done_callback(lambda f: asyncio.create_task(action(f.result())))
        return self

class AsyncSequenceWithoutTemp(Generic[R]):
    pass
