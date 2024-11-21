Here is a translation of the Java code into equivalent Python:

```Python
import abc
from typing import Any, Dict, List, Tuple

class ConfigurableFactory(abc.ABC):
    @property
    def brief(self) -> str:
        return self._get_brief()

    @brief.setter
    def brief(self, value: str) -> None:
        self._set_brief(value)

    @property
    def html_details(self) -> str:
        return self._get_html_details()

    @html_details.setter
    def html_details(self, value: str) -> None:
        self._set_html_details(value)

    def _get_brief(self) -> str:
        try:
            factory_description = type(self).factory_description
            if factory_description is not None:
                return factory_description.brief()
            else:
                return f"Class: {type(self).__name__}"
        except AttributeError:
            return f"Un-described factory: {type(self).__name__}"

    def _set_brief(self, value: str) -> None:
        try:
            type(self).factory_description = FactoryDescription(brief=value)
        except AttributeError:
            pass

    def _get_html_details(self) -> str:
        try:
            factory_description = type(self).factory_description
            if factory_description is not None:
                return factory_description.html_details()
            else:
                return f"Un-described factory: {type(self).__name__}"
        except AttributeError:
            return f"Un-described factory: {type(self).__name__}"

    def _set_html_details(self, value: str) -> None:
        try:
            type(self).factory_description = FactoryDescription(html_details=value)
        except AttributeError:
            pass

    @abc.abstractmethod
    async def build(self) -> Any:
        ...

    def get_options(self) -> Dict[str, 'Property[Any]']:
        options = {}
        for field in dir(type(self)):
            if not hasattr(getattr(type(self), field), '__call__'):
                continue
            factory_option = getattr(getattr(type(self), field), 'factory_option')
            if factory_option is None:
                continue
            try:
                value = getattr(self, field)
                options[factory_option.value] = Property(value=value)
            except AttributeError:
                pass
        return options

    def write_config_state(self, save_state: Any) -> None:
        for option in self.get_options().values():
            codec = ConfigStateField.get_codec_by_type(type(option.value))
            if codec is not None:
                codec.write(save_state, option.key, option.value)

    def read_config_state(self, save_state: Any) -> None:
        for option in self.get_options().values():
            codec = ConfigStateField.get_codec_by_type(type(option.value))
            if codec is not None:
                value = codec.read(save_state, option.key, None)
                if value is not None:
                    option.set_value(value)


class FactoryDescription:
    def __init__(self, brief: str, html_details: str):
        self.brief = brief
        self.html_details = html_details


class Property(abc.ABC):
    @property
    @abc.abstractmethod
    def value_class(self) -> Any:
        ...

    @value_class.setter
    @abc.abstractmethod
    def value_class(self, value: Any) -> None:
        ...

    @property
    @abc.abstractmethod
    def value(self) -> Any:
        ...

    @value.setter
    @abc.abstractmethod
    def value(self, value: Any) -> None:
        ...

    @property
    @abc.abstractmethod
    def enabled(self) -> bool:
        ...

    @enabled.setter
    @abc.abstractmethod
    def enabled(self, value: bool) -> None:
        ...

    @staticmethod
    @abc.abstractclassmethod
    async def from_accessors(cls, cls_: Any, getter: callable, setter: callable) -> 'Property[Any]':
        ...
```

Please note that this is a translation of the Java code into equivalent Python. The actual implementation may vary depending on your specific requirements and constraints.

Also, please be aware that Python does not have direct equivalents to some Java features like annotations (`@Retention`, `@Target`, etc.) or abstract classes with methods declared as `abstract`. Instead, we use docstrings for documentation purposes and type hints for static analysis.