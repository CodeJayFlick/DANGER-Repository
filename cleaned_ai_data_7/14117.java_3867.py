import unittest
from datetime import timedelta

class EventEmitterTest:
    def __init__(self, special_day: str, event: object, factory_with_default_observer: callable, 
                 factory_without_default_observer: callable):
        self.special_day = special_day
        self.event = event
        self.factory_with_default_observer = factory_with_default_observer
        self.factory_without_default_observer = factory_without_default_observer

    def test_all_days(self):
        self.test_all_days_without_default_observer(self.special_day, self.event)
        self.test_all_days_with_default_observer(self.special_day, self.event)

    def test_all_days_without_default_observer(self, special_day: str, event: object):
        observer1 = unittest.mock.Mock()
        observer2 = unittest.mock.Mock()

        emitter = self.factory_without_default_observer()
        emitter.register(observer1)
        emitter.register(observer2)

        for weekday in ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]:
            if weekday == special_day:
                observer1.on_event.assert_called_once_with(event)
                observer2.on_event.assert_called_once_with(event)
            else:
                unittest.mock.verify_zero_interactions([observer1, observer2])

        unittest.mock.verify_no_more_interactions([observer1, observer2])

    def test_all_days_with_default_observer(self, special_day: str, event: object):
        default_observer = unittest.mock.Mock()
        observer1 = unittest.mock.Mock()
        observer2 = unittest.mock.Mock()

        emitter = self.factory_with_default_observer(default_observer)
        emitter.register(observer1)
        emitter.register(observer2)

        for weekday in ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]:
            if weekday == special_day:
                default_observer.on_event.assert_called_once_with(event)
                observer1.on_event.assert_called_once_with(event)
                observer2.on_event.assert_called_once_with(event)
            else:
                unittest.mock.verify_zero_interactions([default_observer, observer1, observer2])

        unittest.mock.verify_no_more_interactions([default_observer, observer1, observer2])
