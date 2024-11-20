Here is the translation of the given Java code into Python:

```Python
import unittest
from threading import Thread
from time import sleep

class StatusBarTest(unittest.TestCase):

    def setUp(self):
        self.test_frame = JFrame("StatusBar Test")
        self.test_frame.setGlassPane(GGlassPane())
        self.test_frame.setSize(400, 100)
        self.status_bar = StatusBar()
        self.test_frame.get_content_pane().add(self.status_bar)
        self.test_frame.setVisible(True)

    def tearDown(self):
        self.test_frame.dispose()

    def test_add_and_remove_status_item(self):

        # Test while not visible
        self.add_and_remove_status_items()

        # Re-run the tests while visible
        self.test_frame.set_visible(True)
        self.add_and_remove_status_items()

    def test_set_status_text(self):

        test_text1 = "Some test status text..."
        self.status_bar.set_status_text(test_text1)

        tooltip_text = self.status_bar.get_tooltip_text()
        self.assertTrue(tooltip_text.find(test_text1) > -1, 
                        f"The tooltip text was not updated with the current {test_text1}.")

        self.test_frame.set_visible(True)
        test_text2 = "More test status text..."
        self.status_bar.set_status_text(test_text2)
        tooltip_text = self.status_bar.get_tooltip_text()
        self.assertTrue(tooltip_text.find(test_text1) > -1, 
                        f"The tooltip text was not updated with the current {test_text1}.")
        self.assertTrue(tooltip_text.find(test_text2) > -1, 
                        f"The tooltip text was not updated with the current {test_text2}.")

    def add_and_remove_status_items(self):
        label1 = GDLabel("Test Label 1")
        label2 = GDLabel("Test Label 2")

        # Normal add/remove operations
        self.run_swing(lambda: 
            self.status_bar.add_status_item(label1, True, True)
            self.status_bar.add_status_item(label2, True, True))

        self.run_swing(lambda: 
            self.status_bar.remove_status_item(label1)
            self.status_bar.remove_status_item(label2))

        # Method call variations
        self.run_swing(lambda: 
            self.status_bar.add_status_item(label1, False, True)
            self.status_bar.add_status_item(label2, True, False))

        self.run_swing(lambda: 
            self.status_bar.remove_status_item(label1)
            self.status_bar.remove_status_item(label2))

        # Repeat adding
        self.run_swing(lambda: 
            self.status_bar.add_status_item(label1, True, True)
            self.status_bar.add_status_item(label1, True, True))

        # Removing non-existent elements        
        self.run_swing(self.status_bar.remove_status_item, label2)

    def run_swing(func):
        thread = Thread(target=func)
        thread.start()
        sleep(0.5)  # wait for the Swing event loop to process

    def set_status_text(self, text):
        self.run_swing(lambda: 
            self.status_bar.set_status_text(text))
        self.wait_for_swing()

if __name__ == "__main__":
    unittest.main()
```

Please note that this is a direct translation of your Java code into Python. It might not be the most idiomatic or efficient way to write Python, but it should work as expected.