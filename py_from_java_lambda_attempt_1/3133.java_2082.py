Here is a translation of the provided Java code into equivalent Python:

```Python
class AbstractBinaryFormatAnalyzer:
    def __init__(self, command):
        self.command = command

    def added(self, program: 'Program', set: 'AddressSetView', monitor: 'TaskMonitor', log: 'MessageLog') -> bool:
        try:
            return self.command.apply_to(program, monitor)
        except Exception as e:
            log.append_exception(e)
            log.status = str(e)

        finally:
            log.copy_from(self.command.get_messages())

    def can_analyze(self, program: 'Program') -> bool:
        return self.command.can_apply(program)

    def get_default_enablement(self, program: 'Program') -> bool:
        return self.command.can_apply(program)
```

Please note that Python does not have direct equivalent of Java's abstract classes and interfaces. However, we can achieve similar functionality using inheritance in Python.

Also, the `@Override` annotation is used to indicate that a method overrides or implements one from its parent class. In Python, this concept doesn't exist explicitly but it can be achieved by naming your methods exactly as they are named in their parent classes (in case of overriding) and providing implementation for them if you're implementing an interface.

Lastly, the `CancelledException` is not present in Python's standard library so we didn't include any exception handling code here.