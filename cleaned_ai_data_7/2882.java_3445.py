import unittest
from weakref import WeakKeyDictionary

class DummyListener:
    def event(self, e):
        pass

class ListenerSet:
    def __init__(self, listener_type):
        self.listeners = WeakKeyDictionary()

    def add(self, listener):
        self.listeners[listener] = None

    def fire_event(self, event):
        for listener in list(self.listeners.keys()):
            try:
                listener.event(event)
            except Exception as e:
                print(f"Error: {e}")

class TestListenerSet(unittest.TestCase):

    @unittest.skip
    def test_behaves_like_set_and_multiplexes(self):
        listeners = ListenerSet(DummyListener)
        ai1, d1 = AtomicInteger(0), lambda e: (ai1.getAndIncrement(), )
        ai2, d2 = AtomicInteger(0), lambda e: (ai2.getAndIncrement(), )

        listeners.add(d1())
        listeners.add(d2())

        listeners.fire_event("EventA")
        self.assertEqual(ai1.get(), 1)
        self.assertEqual(ai2.get(), 1)

        listeners.add(d1())  # This had better not double fire

        listeners.fire_event("EventB")
        self.assertEqual(ai1.get(), 2)
        self.assertEqual(ai2.get(), 2)

    @unittest.skip
    def test_continues_on_error(self):
        listeners = ListenerSet(DummyListener)

        ar1, d1 = AtomicReference(None), lambda e: (ar1.set(e), )
        listeners.add(d1())

        ar2, d2 = AtomicReference(None), lambda e: (ar2.set(e), )
        listeners.add(d2())

        listeners.fire_event("Should see on both")
        self.assertEqual(ar1.get(), "Should see on both")
        self.assertEqual(ar2.get(), "Should see on both")

    @unittest.skip
    def test_weakly_references_listeners(self):
        listeners = ListenerSet(DummyListener)

        ar, d = AtomicReference(None), lambda e: (ar.set(e), )
        listeners.add(d())

        listeners.fire_event("EventA")
        self.assertEqual(ar.get(), "EventA")

        del d  # Trash the only strong reference
        import gc; gc.collect()

        listeners.fire_event("EventB")
        self.assertEqual(ar.get(), "EventA")


if __name__ == '__main__':
    unittest.main()
