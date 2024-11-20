Here is the translation of the Java interface `MagicService` into a Python class:

```python
class MagicService:
    def __init__(self):
        pass  # No initialization needed in this case

    def find_all_wizards(self) -> list:
        return []  # Replace with actual implementation to retrieve all wizards

    def find_all_spellbooks(self) -> list:
        return []  # Replace with actual implementation to retrieve all spellbooks

    def find_all_spells(self) -> list:
        return []  # Replace with actual implementation to retrieve all spells

    def find_wizards_with_spellbook(self, name: str) -> list:
        return []  # Replace with actual implementation to retrieve wizards with a specific spellbook

    def find_wizards_with_spell(self, name: str) -> list:
        return []  # Replace with actual implementation to retrieve wizards with a specific spell
```

Note that I've replaced the Java `List` types with Python's built-in `list`, and removed the `public` access modifier since it is not needed in Python. The method implementations are also simplified, as they would typically involve database queries or other operations depending on your use case.