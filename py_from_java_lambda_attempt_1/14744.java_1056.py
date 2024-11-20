Here is the translation of the given Java code into Python:

```Python
import asyncio
from unittest import TestCase
from concurrent.futures import ThreadPoolExecutor, as_completed


class PromiseTest(TestCase):

    def setUp(self):
        self.executor = ThreadPoolExecutor()
        self.promise = None

    async def test_promise_is_fulfilled_with_the_resultant_value_of_executing_the_task(self):
        awaitable = asyncio.create_task(self.number_crunching_task())
        self.promise = awaitable
        result = await self.promise
        self.assertEqual(result, NumberCrunchingTask.CRUNCHED_NUMBER)
        self.assertTrue(await self.promise.done())
        self.assertFalse(await self.promise.cancelled())

    async def test_promise_is_fulfilled_with_an_exception_if_task_throws_an_exception(self):
        try:
            await asyncio.wait_for(self.number_crunching_task(), timeout=1.0)
            self.fail("Fetching promise should result in exception if the task threw an exception")
        except Exception as e:
            self.assertTrue(await self.promise.done())
            self.assertFalse(await self.promise.cancelled())

    async def test_dependent_promise_is_fulfilled_after_the_consumer_consumes_the_result_of_this_promise(self):
        dependent_promise = awaitable.then(lambda x: asyncio.create_task(self.number_crunching_task()))
        result = await dependent_promise
        self.assertEqual(result, NumberCrunchingTask.CRUNCHED_NUMBER)
        self.assertTrue(await dependent_promise.done())
        self.assertFalse(await dependent_promise.cancelled())

    async def test_dependent_promise_is_fulfilled_with_an_exception_if_consumer_throws_an_exception(self):
        try:
            await asyncio.wait_for(dependent_promise, timeout=1.0)
            self.fail("Fetching dependent promise should result in exception if the action threw an exception")
        except Exception as e:
            self.assertTrue(await self.promise.done())
            self.assertFalse(await self.promise.cancelled())

    async def test_dependent_promise_is_fulfilled_after_the_function_transforms_the_result_of_this_promise(self):
        dependent_promise = awaitable.then(lambda x: asyncio.create_task(str(x)))
        result = await dependent_promise
        self.assertEqual(result, str(NumberCrunchingTask.CRUNCHED_NUMBER))
        self.assertTrue(await dependent_promise.done())
        self.assertFalse(await dependent_promise.cancelled())

    async def test_dependent_promise_is_fulfilled_with_an_exception_if_function_throws_exception(self):
        try:
            await asyncio.wait_for(dependent_promise, timeout=1.0)
            self.fail("Fetching dependent promise should result in exception if the function threw an exception")
        except Exception as e:
            self.assertTrue(await self.promise.done())
            self.assertFalse(await self.promise.cancelled())

    async def test_fetching_an_already_fulfilled_promise_returns_the_fulfilled_value_immediately(self):
        awaitable = asyncio.create_task(lambda: NumberCrunchingTask.CRUNCHED_NUMBER)
        result = await awaitable
        self.assertEqual(result, NumberCrunchingTask.CRUNCHED_NUMBER)

    @asyncio.coroutine
    def number_crunching_task(self):
        # Do number crunching
        yield from asyncio.sleep(1.0)
        return NumberCrunchingTask.CRUNCHED_NUMBER


class NumberCrunchingTask:
    CRUNCHED_NUMBER = 100000

    async def __call__(self):
        await asyncio.sleep(1.0)
        return self.CRUNCHED_NUMBER
```

Please note that Python's `asyncio` module is used to create asynchronous tasks and handle concurrent execution of promises.