import unittest
from typing import Any

class ActionBuilderTest(unittest.TestCase):
    def setUp(self) -> None:
        self.action_count = 0

    def test_description(self) -> None:
        action = ActionBuilder("Test", "Test").description("foo").on_action(lambda e: self.action_count += 1).build()
        self.assertEqual(action.get_description(), "foo")

    def test_menu_path(self) -> None:
        action = ActionBuilder("Test", "Test").menu_path("foo", "bar").on_action(lambda e: self.action_count += 1).build()
        data = action.get_menu_bar_data()
        self.assertEqual(data.get_menu_path_as_string(), "foo->bar")

    def test_menu_group(self) -> None:
        action = ActionBuilder("Test", "Test").menu_path("foo", "bar").menu_group("A", "B").on_action(lambda e: self.action_count += 1).build()
        data = action.get_menu_bar_data()
        self.assertEqual(data.get_menu_group(), "A")
        self.assertEqual(data.get_menu_subgroup(), "B")

    def test_menu_icon(self) -> None:
        action = ActionBuilder("Test", "Test").menu_path("foo", "bar").menu_icon(Icons.ADD_ICON).on_action(lambda e: self.action_count += 1).build()
        data = action.get_menu_bar_data()
        self.assertEqual(data.get_menu_icon(), Icons.ADD_ICON)

    def test_popup_path(self) -> None:
        action = ActionBuilder("Test", "Test").popup_menu_path("foo", "bar").on_action(lambda e: self.action_count += 1).build()
        data = action.get_popup_menu_data()
        self.assertEqual(data.get_menu_path_as_string(), "foo->bar")

    def test_popup_group(self) -> None:
        action = ActionBuilder("Test", "Test").popup_menu_path("foo", "bar").popup_menu_group("A", "B").on_action(lambda e: self.action_count += 1).build()
        data = action.get_popup_menu_data()
        self.assertEqual(data.get_menu_group(), "A")
        self.assertEqual(data.get_menu_subgroup(), "B")

    def test_popup_icon(self) -> None:
        action = ActionBuilder("Test", "Test").popup_menu_path("foo", "bar").popup_menu_icon(Icons.ADD_ICON).on_action(lambda e: self.action_count += 1).build()
        data = action.get_popup_menu_data()
        self.assertEqual(data.get_menu_icon(), Icons.ADD_ICON)

    def test_toolbar_icon(self) -> None:
        action = ActionBuilder("Test", "Test").toolbar_icon(Icons.ADD_ICON).on_action(lambda e: self.action_count += 1).build()
        data = action.get_tool_bar_data()
        self.assertEqual(data.get_icon(), Icons.ADD_ICON)

    def test_toolbar_group(self) -> None:
        action = ActionBuilder("Test", "Test").toolbar_icon(Icons.ADD_ICON).toolbar_group("A", "B").on_action(lambda e: self.action_count += 1).build()
        data = action.get_tool_bar_data()
        self.assertEqual(data.get_tool_bar_group(), "A")
        self.assertEqual(data.get_tool_bar_subgroup(), "B")

    def test_key_binding(self) -> None:
        action = ActionBuilder("Test", "Test").key_binding(KeyStroke.getKeyStroke("A")).on_action(lambda e: self.action_count += 1).build()
        self.assertEqual(action.get_key_binding(), KeyStroke.getKeyStroke("A"))

    def test_on_action(self) -> None:
        action = ActionBuilder("Test", "Test").on_action(lambda e: self.action_count = 6).build()
        self.assertEqual(self.action_count, 0)
        action.action_performed(ActionContext())
        self.assertEqual(self.action_count, 6)

    def test_enabled(self) -> None:
        action = ActionBuilder("Test", "Test").enabled(True).on_action(lambda e: self.action_count += 1).build()
        self.assertTrue(action.is_enabled())

        action = ActionBuilder("Test", "Test").enabled(False).on_action(lambda e: self.action_count += 1).build()
        self.assertFalse(action.is_enabled())

    def test_enabled_when(self) -> None:
        action = ActionBuilder("Test", "Test").enabled_when(lambda c: c.get_context_object() == this).on_action(lambda e: self.action_count += 1).build()

        self.assertTrue(action.is_enabled_for_context(ActionContext(this, None)))
        self.assertFalse(action.is_enabled_for_context(ActionContext()))

    def test_valid_context_when(self) -> None:
        action = ActionBuilder("Test", "Test").valid_context_when(lambda c: c.get_context_object() == this).on_action(lambda e: self.action_count += 1).build()

        self.assertTrue(action.is_valid_context(ActionContext(this, None)))
        self.assertFalse(action.is_valid_context(ActionContext()))

    def test_popup_when(self) -> None:
        action = ActionBuilder("Test", "Test").popup_when(lambda c: c.get_context_object() == this).on_action(lambda e: self.action_count += 1).build()

        self.assertTrue(action.is_add_to_popup(ActionContext(this, None)))
        self.assertFalse(action.is_add_to_popup(ActionContext()))

    def test_with_context(self) -> None:
        action = ActionBuilder("Test", "Test").with_context(FooActionContext)
        .enabled_when(lambda c: c.foo())
        .on_action(lambda e: self.action_count += 1).build()

        self.assertFalse(action.is_enabled_for_context(ActionContext()))
        self.assertTrue(action.is_enabled_for_context(FooActionContext()))

    def test_manual_enablement(self) -> None:
        action = ActionBuilder("Test", "Test").on_action(lambda e: self.action_count += 1).enabled(False).build()
        self.assertFalse(action.is_enabled())
        action.set_enabled(True)
        self.assertTrue(action.is_enabled())

class FooActionContext(ActionContext):
    def foo(self) -> bool:
        return True

if __name__ == "__main__":
    unittest.main()
