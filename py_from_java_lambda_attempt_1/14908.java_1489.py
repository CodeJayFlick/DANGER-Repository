Here is the translation of the given Java code into Python:

```Python
class MagicService:
    def __init__(self, wizard_dao: 'WizardDAO', spellbook_dao: 'SpellbookDAO', spell_dao: 'SpellDAO'):
        self.wizard_dao = wizard_dao
        self.spellbook_dao = spellbook_dao
        self.spell_dao = spell_dao

    def find_all_wizards(self) -> list:
        return self.wizard_dao.find_all()

    def find_all_spellbooks(self) -> list:
        return self.spellbook_dao.find_all()

    def find_all_spells(self) -> list:
        return self.spell_dao.find_all()

    def find_wizards_with_spellbook(self, name: str) -> list:
        spellbook = self.spellbook_dao.find_by_name(name)
        return [wizard for wizard in spellbook.wizards]

    def find_wizards_with_spell(self, name: str) -> list:
        spell = self.spell_dao.find_by_name(name)
        spellbook = spell.spellbook
        return [wizard for wizard in spellbook.wizards]
```

Note that Python does not have direct equivalents to Java's `List` and `ArrayList`, so I've used the built-in `list` type instead. Also, Python is dynamically typed, so you don't need to specify types like you do in Java.

The DAO classes (`WizardDAO`, `SpellbookDAO`, etc.) are assumed to be implemented elsewhere in your codebase, but their methods should match those called here (e.g., `find_all()`, `find_by_name(name)`).