import time
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC


class CommentsPluginScreenShots:
    def __init__(self):
        pass

    def test_capture_comment(self, driver):
        position_listing_top(0x401000)
        perform_action("Edit Comments", "CommentsPlugin", False)
        capture_dialog()

    def test_show_comment_history(self, driver):
        set_comment_field_text("This is my first comment.", 0x401000)
        time.sleep(1)  # equivalent to sleep(1000)
        set_comment_field_text("This is my second comment.", 0x401000)

        perform_action("Show Comment History", "CommentsPlugin", False)
        capture_dialog()

    def set_comment_field_text(self, text, addr):
        driver.find_element_by_xpath("//input[@name='comment']").send_keys(text + Keys.RETURN)
        time.sleep(1)  # equivalent to sleep(1000)

    def position_listing_top(self, address):
        pass

    def perform_action(self, action_name, plugin_name, is_modal=False):
        pass

    def capture_dialog(self):
        pass


# Usage
driver = webdriver.Chrome()  # replace with your preferred browser
plugin_screen_shots = CommentsPluginScreenShots()
plugin_screen_shots.test_capture_comment(driver)
plugin_screen_shots.test_show_comment_history(driver)

