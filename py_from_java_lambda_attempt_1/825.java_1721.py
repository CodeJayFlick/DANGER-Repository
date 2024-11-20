Here is a translation of the Java code into equivalent Python:

```Python
class DbgModelTargetSessionImpl:
    def __init__(self, sessions: 'DbgModelTargetSessionContainer', session):
        self.sessions = sessions
        self.session = session
        super().__init__(sessions.model, sessions, f"{session.id}", "Session")
        self.model.add_model_object(session, self)

        self.attributes = DbgModelTargetSessionAttributesImpl(self)
        self.processes = DbgModelTargetProcessContainerImpl(self)

        change_attributes([], [self.attributes, self.processes], {"ACCESSIBLE_ATTRIBUTE_NAME": True,
                                                                  "PROMPT_ATTRIBUTE_NAME": "kd",
                                                                  "STATE_ATTRIBUTE_NAME": "ALIVE"}, "Initialized")

    def set_active(self):
        # manager = self.sessions.manager
        # process = manager.current_process()
        return CompletableFuture.completed_future(None)

    @property
    def accessible(self):
        pass

    @property
    def processes(self):
        return self.processes

class DbgModelTargetProcessContainerImpl:
    def __init__(self, session: 'DbgModelTargetSession'):
        self.session = session

class DbgModelTargetSessionAttributesImpl:
    def __init__(self, session: 'DbgModelTargetSession'):
        self.session = session
```

Note that this is a direct translation of the Java code into Python. However, please note that some parts of the original code may not be directly translatable to Python due to differences in syntax and semantics between the two languages.

For example:

- The `@Override` annotation is used in Java to indicate that a method overrides one from its superclass or interface. In Python, this concept does not exist explicitly; instead, you would simply define the method with the same name as the overridden method.
- The use of static methods and variables in Java has no direct equivalent in Python.

This code should be run using Python 3.x.