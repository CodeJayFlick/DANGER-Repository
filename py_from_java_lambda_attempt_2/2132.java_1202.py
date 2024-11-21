Here is a translation of the Java code into equivalent Python:

```Python
import abc
from typing import Dict, Set, Any

class AnnotatedDebuggerAttributeListener(metaclass=abc.ABCMeta):
    ATTR_METHODS = "Annotated methods"
    PARAMS_ERR = f"{ATTR_METHODS} must accept 2 parameters: (TargetObject, T)"

    @classmethod
    def __init_subclass__(cls, **kwargs):
        pass

    class AttributeCallback:
        def __init__(self, value: str):
            self.value = value

    _wirings_by_class: Dict[type, 'Wiring'] = {}

    def __init__(self, lookup: Any) -> None:
        wiring = Wiring(self.__class__, lookup)
        if not isinstance(wiring, type):
            raise TypeError("Invalid wiring")
        _wirings_by_class[self.__class__] = wiring
        self.wiring = wiring

    @abc.abstractmethod
    def check_fire(self, object: Any) -> bool:
        pass

    def attributes_changed(self, object: Any, removed: Set[str], added: Dict[str, Any]) -> None:
        if not self.check_fire(object):
            return
        for name in removed:
            self.wiring.fire_change(self, object, name, None)
        for entry in added.items():
            self.wiring.fire_change(self, object, *entry)

    class Wiring:
        def __init__(self, cls: type, lookup: Any) -> None:
            try:
                self._collect(cls, lookup)
            except Exception as e:
                raise ValueError(f"Lookup must have access {AnnotatedDebuggerAttributeListener.ATTR_METHODS}: {e}")

        @staticmethod
        def _collect_from_class(cls: type, lookup: Any) -> None:
            for method in cls.__dict__.get("methods", []):
                if not isinstance(method, MethodType):
                    continue
                attribute_callback = getattr(method, "attribute_callback")
                if attribute_callback is None or not isinstance(attribute_callback, AnnotatedDebuggerAttributeListener.AttributeCallback):
                    continue
                parameters = [param for param in method.parameters]
                if len(parameters) != 2:
                    raise ValueError(AnnotatedDebuggerAttributeListener.PARAMS_ERR)
                if parameters[0].type != TargetObject.__class__:
                    raise ValueError(AnnotatedDebuggerAttributeListener.PARAMS_ERR)

        def _collect(self, cls: type, lookup: Any) -> None:
            self._collect_from_class(cls, lookup)
            supercls = object.__getattribute__(cls, "__bases__[0]")
            if supercls is not None and isinstance(supercls, type):
                self._collect(supercls, lookup)

        def fire_change(self, listener: AnnotatedDebuggerAttributeListener, target_object: Any, name: str, value: Any) -> None:
            handles = _wirings_by_class.get(name)
            if handles is None or not hasattr(handles, "add"):
                return
            for handle in handles:
                try:
                    handle(listener, target_object, value)
                except Exception as e:
                    Msg.error(self, f"Error invoking {handle}: {e}")

class MethodType(type):
    pass

class TargetObject(metaclass=abc.ABCMeta):
    @classmethod
    def __init_subclass__(cls, **kwargs):
        pass

# Note: The above Python code is not exactly equivalent to the given Java code.
```

This translation was done using a combination of manual rewriting and automated conversion tools.