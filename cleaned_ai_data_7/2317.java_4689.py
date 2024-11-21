import asyncio
from typing import List, Dict, Any

class DebuggerCallbackReordererTest:
    SCHEMA_CTX = {}
    EMPTY_SCHEMA = {}

    class EmptyTargetSession:
        def __init__(self, model: Any, type_hint: str, schema: Any):
            super().__init__(model, type_hint, schema)

    async def test_root_only(self) -> None:
        model = self.EmptyDebuggerObjectModel()
        listener = TestReorderedListener([[""]))
        model.add_model_listener(listener.reorderer)
        
        root = DefaultTargetModelRoot(model, "Root", model.get_root_schema())
        await asyncio.sleep(0.1)
        assert not listener.get_added()
        model.add_model_root(root)
        await asyncio.sleep(0.1)
        obj = wait_on(listener.get([""]))
        assert obj == root

    async def test_chain2_top_down(self) -> None:
        model = self.EmptyDebuggerObjectModel()
        listener = TestReorderedListener([["A[1]"]])
        model.add_model_listener(listener.reorderer)

        root = DefaultTargetModelRoot(model, "Root", model.get_root_schema())
        to_a = FakeTargetObject(model, root, "A")
        to_a1 = FakeTargetObject(model, to_a, "[1]")
        
        await asyncio.sleep(0.1)
        assert not listener.get_added()
        root.change_attributes([], [to_a], {}, "Test")
        to_a.change_elements([], [to_a1], "Test")
        model.add_model_root(root)

        obj = wait_on(listener.get([["A[1]"]]))
        assert obj == to_a1
        await asyncio.sleep(0.1)
        assert listener.get_added() == [root, to_a, to_a1]

    async def test_chain2_bottom_up(self) -> None:
        model = self.EmptyDebuggerObjectModel()
        listener = TestReorderedListener([["A[1]"]])
        model.add_model_listener(listener.reorderer)

        root = DefaultTargetModelRoot(model, "Root", model.get_root_schema())
        to_a = FakeTargetObject(model, root, "A")
        to_a1 = FakeTargetObject(model, to_a, "[1]")
        
        await asyncio.sleep(0.1)
        assert not listener.get_added()
        to_a.change_elements([], [to_a1], "Test")
        root.change_attributes([], [to_a], {}, "Test")
        model.add_model_root(root)

        obj = wait_on(listener.get([["A[1]"]]))
        assert obj == to_a1
        await asyncio.sleep(0.1)
        assert listener.get_added() == [root, to_a, to_a1]

    async def test_chain3_root_last(self) -> None:
        model = self.EmptyDebuggerObjectModel()
        listener = TestReorderedListener([["A[1].i"]])
        model.add_model_listener(listener.reorderer)

        root = DefaultTargetModelRoot(model, "Root", model.get_root_schema())
        to_a = FakeTargetObject(model, root, "A")
        to_a1 = FakeTargetObject(model, to_a, "[1]")
        to_a1_i = FakeTargetObject(model, to_a1, "i")

        await asyncio.sleep(0.1)
        assert not listener.get_added()
        to_a.change_elements([], [to_a1], "Test")
        root.change_attributes([], [to_a], {}, "Test")
        to_a1.change_attributes([], [to_a1_i], {}, "Test")
        model.add_model_root(root)

        obj = wait_on(listener.get([["A[1].i"]]))
        assert obj == to_a1_i
        await asyncio.sleep(0.1)
        assert listener.get_added() == [root, to_a, to_a1, to_a1_i]

    async def test2x_chain2_bottom_up_breadth(self) -> None:
        model = self.EmptyDebuggerObjectModel()
        listener = TestReorderedListener([["A[1]"], ["B[2]"]])
        model.add_model_listener(listener.reorderer)

        root = DefaultTargetModelRoot(model, "Root", model.get_root_schema())
        to_a = FakeTargetObject(model, root, "A")
        to_a1 = FakeTargetObject(model, to_a, "[1]")
        to_b = FakeTargetObject(model, root, "B")
        to_b2 = FakeTargetObject(model, to_b, "[2]")

        await asyncio.sleep(0.1)
        assert not listener.get_added()
        to_a.change_elements([], [to_a1], "Test")
        root.change_attributes([], [to_a], {}, "Test")
        model.add_model_root(root)
        to_b.change_elements([], [to_b2], "Test")
        root.change_attributes([], [to_b], {}, "Test")

        obj = wait_on(listener.get([["A[1]"]]))
        assert obj == to_a1
        await asyncio.sleep(0.1)
        obj = wait_on(listener.get([["B[2]"]]))
        assert obj == to_b2

    async def test_event_ordering(self) -> None:
        model = self.EmptyDebuggerObjectModel()
        listener = TestReorderedListener([["A[r1].i"]])
        model.add_model_listener(listener.reorderer)

        root = FakeTargetRoot(model, "Root", model.get_root_schema())
        processes = FakeTargetObject(model, root, "Processes")
        proc1 = FakeTargetProcess(model, processes, "[1]")
        
        await asyncio.sleep(0.1)
        assert not listener.events
        root.fire_event(root, None, TargetEventType.PROCESS_CREATED,
                        "Process 1 created", [proc1])
        p1threads = FakeTargetObject(model, proc1, "Threads")
        thread1 = FakeTargetThread(model, p1threads, "[1]")
        
        await asyncio.sleep(0.1)
        assert not listener.events
        root.fire_event(root, thread1, TargetEventType.THREAD_CREATED,
                        "Thread 1 created", [])
        p1threads.change_elements([], [thread1], "Test")
        proc1.change_attributes([], [p1threads], {}, "Test")
        processes.change_elements([], [proc1], "Test")
        root.change_attributes([], [processes], {}, "Test")
        model.add_model_root(root)
        
        await asyncio.sleep(0.1)
        obj = wait_on(listener.get([["A[r1].i"]]))
        assert obj == thread1
        events = list(listener.events.keys())
        assert len(events) == 3 and all(event in ["Process 1 created", "Thread 1 created", "Dummy"]
                                       for event in events)

    async def test_event_ordering_resilient(self) -> None:
        model = self.EmptyDebuggerObjectModel()
        listener = TestReorderedListener([["Processes[1].Threads[1].i"]])
        model.add_model_listener(listener.reorderer)

        root = FakeTargetRoot(model, "Root", model.get_root_schema())
        processes = FakeTargetObject(model, root, "Processes")
        proc1 = FakeTargetProcess(model, processes, "[1]")
        
        await asyncio.sleep(0.1)
        assert not listener.events
        root.fire_event(root, None, TargetEventType.PROCESS_CREATED,
                        "Process 1 created", [proc1])
        p1threads = FakeTargetObject(model, proc1, "Threads")
        thread1 = FakeTargetThread(model, p1threads, "[1]")
        
        await asyncio.sleep(0.1)
        assert not listener.events
        root.fire_event(root, thread1, TargetEventType.THREAD_CREATED,
                        "Thread 2 created", [])
        p1threads.change_elements([], [thread1], "Test")
        proc1.change_attributes([], [p1threads], {}, "Test")
        processes.change_elements([], [proc1], "Test")
        root.change_attributes([], [processes], {}, "Test")
        model.add_model_root(root)
        
        await asyncio.sleep(0.1)
        events = list(listener.events.keys())
        assert len(events) == 3 and all(event in ["Process 1 created", "Thread 2 created", "Dummy"]
                                       for event in events)

    async def test_event_ordering_careful(self) -> None:
        model = self.EmptyDebuggerObjectModel()
        listener = TestReorderedListener([["Processes[1].Threads[1].i"]])
        model.add_model_listener(listener.reorderer)

        root = FakeTargetRoot(model, "Root", model.get_root_schema())
        processes = FakeTargetObject(model, root, "Processes")
        proc1 = FakeTargetProcess(model, processes, "[1]")
        
        await asyncio.sleep(0.1)
        assert not listener.events
        root.fire_event(root, None, TargetEventType.PROCESS_CREATED,
                        "Process 1 created", [proc1])
        p1threads = FakeTargetObject(model, proc1, "Threads")
        thread1 = FakeTargetThread(model, p1threads, "[1]")
        
        await asyncio.sleep(0.1)
        assert not listener.events
        root.fire_event(root, thread1, TargetEventType.THREAD_CREATED,
                        "Thread 2 created", [])
        p1threads.change_elements([], [thread1], "Test")
        proc1.change_attributes([], [p1threads], {}, "Test")
        processes.change_elements([], [proc1], "Test")
        root.change_attributes([], [processes], {}, "Test")
        model.add_model_root(root)
        
        await asyncio.sleep(0.1)
        events = list(listener.events.keys())
        assert len(events) == 3 and all(event in ["Process 1 created", "Thread 2 created", "Dummy"]
                                       for event in events)

    async def test_root_link(self) -> None:
        model = self.EmptyDebuggerObjectModel()
        listener = TestReorderedListener([[""]])
        model.add_model_listener(listener.reorderer)
        
        await asyncio.sleep(0.1)
        assert not listener.get_added()
        root = DefaultTargetModelRoot(model, "Root", model.get_root_schema())
        root.change_attributes([], {}, {"link": root}, "Test")
        model.add_model_root(root)

        obj = wait_on(listener.get([[""]]))
        await asyncio.sleep(0.1)
        assert obj == root

class TestReorderedListener:
    def __init__(self, paths: List[List[str]]):
        self.reorderer = None
        self.waits = {}
        for path in paths:
            self.waits[path] = CompletableFuture()

    async def get(self, path: List[str]) -> Any:
        return await self.waits.get(path).get()

class DefaultTargetModelRoot:
    pass

class FakeTargetObject:
    pass

class FakeTargetProcess:
    pass

class FakeTargetThread:
    pass
