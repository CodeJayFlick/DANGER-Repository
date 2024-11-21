Here is the translation of the Java code to Python:
```python
import sys
from typing import List, Dict, Any

class VisualEffects:
    NEW_EFFECT_DATA = Skript.classExists("org.bukkit.block.data.BlockData")
    HAS_REDSTONE_DATA = Skript.classExists("org.bukkit.Particle$DustOptions")

    effect_type_modifiers: Dict[str, callable] = {}
    element_info: SyntaxElementInfo[VisualEffect]
    visual_effect_types: List[VisualEffectType]

    @classmethod
    def register_single_class(cls, class_name: str) -> None:
        Variables.yggdrasil.register_single_class(class_name)

    @staticmethod
    def parse(s: str) -> VisualEffect | None:
        if element_info is None:
            return None
        return SkriptParser.parse_static(Noun.strip_indefinite_article(s), SingleItemIterator(element_info), None)

    @classmethod
    def get(cls, i: int) -> VisualEffectType:
        return visual_effect_types[i]

    @staticmethod
    def get_all_names() -> str:
        names = []
        for visual_effect_type in visual_effect_types:
            names.append(visual_effect_type.name)
        return ", ".join(names)

    @classmethod
    def generate_types(cls) -> None:
        types: List[VisualEffectType] = []
        stream = Stream.of(Effect, EntityEffect, Particle).map(Class.get_enum_constants).flatMap(Arrays.stream).map(VisualEffectType.of).filter(Objects.non_null)
        for type in stream:
            id = type.id
            if effect_type_modifiers.get(id):
                effect_type_modifiers[id].accept(type)

        visual_effect_types = types
        patterns: List[str] = []
        for i, _ in enumerate(visual_effect_types):
            patterns.append(visual_effect_types[i].pattern)
        element_info = SyntaxElementInfo(patterns, VisualEffect, "VisualEffect")

    @classmethod
    def register_colorable(cls, id: str) -> None:
        effect_type_modifiers[id] = lambda type: type.set_colorable()

    @classmethod
    def register_data_supplier(cls, id: str, data_supplier: callable) -> None:
        consumer = lambda type: type.with_data(data_supplier)
        if id in effect_type_modifiers:
            consumer = effect_type_modifiers.get(id).and_then(consumer)

        effect_type_modifiers[id] = consumer

    @classmethod
    def register_single_class(cls, class_name: str) -> None:
        Variables.yggdrasil.register_single_class(class_name)

    @staticmethod
    def main() -> None:
        Language.add_listener(lambda: cls.generate_types())

if __name__ == "__main__":
    VisualEffects.main()
```
Note that I've kept the same variable names and structure as the original Java code, but translated them to Python. Some changes were made to accommodate Python's syntax and semantics:

* The `@Nullable` annotation is not needed in Python.
* The `static` keyword is replaced with a class method (`@classmethod`) or instance method (no decorator).
* The `HashMap` is replaced with a dictionary literal `{}`.
* The `BiFunction` interface is replaced with a simple function that takes two arguments and returns one value.
* The `Consumer` interface is not needed in Python, as we can use lambda functions to achieve the same effect.

Please note that this translation may require some manual adjustments to work correctly.