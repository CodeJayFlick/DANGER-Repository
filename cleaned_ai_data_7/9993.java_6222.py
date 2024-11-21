import unittest


class PlaceholderSetTest(unittest.TestCase):

    def setUp(self):
        self.set = PlaceholderSet(PlaceholderManager(DummyInstaller()))

    def testDedupingRestoredPlaceholders_OnlyOneHidden(self):
        placeholder1 = create_placeholder("A", "1", False)
        self.set.add_restored_placeholder(placeholder1)

        placeholders = self.set.get_unused_placeholders()
        self.assertEqual(len(placeholders), 1, f"Expected {len(placeholders)} but got {placeholders}")
        self.assertTrue(any(p.name == "A" and p.title == "1" for p in placeholders))

    def testRegisterPlaceholders_BrandNew(self):
        placeholder = create_placeholder("A", "1", True)
        provider = TestProvider()
        self.set.placeholder_used(provider, placeholder)

        self.assertEqual(len(self.set.get_unused_placeholders()), 0)
        self.assertEqual(self.set.get_placeholder(provider), placeholder)
        self.assertTrue(placeholder in self.set.get_placeholders())

    def testRegisterPlaceholds_WasInUnusedList(self):
        placeholder = create_placeholder("A", "1", True)
        self.set.add_restored_placeholder(placeholder)

        provider = TestProvider()
        self.set.placeholder_used(provider, placeholder)

        self.assertEqual(len(self.set.get_unused_placeholders()), 0)
        self.assertEqual(self.set.get_placeholder(provider), placeholder)
        self.assertTrue(placeholder in self.set.get_placeholders())

    def testFreePlaceholders(self):
        placeholder = create_placeholder("A", "1", True)
        provider = TestProvider()
        self.set.placeholder_used(provider, placeholder)

        self.assertEqual(len(self.set.get_unused_placeholders()), 0)
        self.assertEqual(self.set.get_placeholder(provider), placeholder)
        self.assertTrue(placeholder in self.set.get_placeholders())

        self.set.placeholder_freed(provider)
        self.assertEqual(len(self.set.get_unused_placeholders()), 1)
        self.assertIsNone(self.set.get_placeholder(provider))

    def contains(self, set, name, title):
        for p in set:
            if p.name == name and p.title == title:
                return True
        return False

    def create_placeholder(self, name, title, show):
        return ComponentPlaceholder(name, "owner", "group", title, show, None, 0)

class DummyInstaller:

    def install_placeholder(self, placeholder, position):
        pass

    def uninstall_placeholder(self, placeholder, keep_around):
        pass


class TestProvider(ComponentProvider):

    def __init__(self):
        super().__init__(None, None, None)
        self.label = GDLabel()

    def get_component(self):
        return self.label
