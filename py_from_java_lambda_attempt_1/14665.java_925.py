Here is the translation of the Java code to Python:
```python
import logging
from htmlunit import WebClient, HtmlPage, HtmlTextInput, HtmlPasswordInput, HtmlSubmitInput

class LoginPage:
    def __init__(self, web_client):
        self.web_client = web_client
        self.page = None

    def navigate_to_page(self):
        try:
            self.page = self.web_client.get_page("file:/" + AUT_PATH + "login.html")
        except Exception as e:
            logging.error("An error occurred on navigate_to_page.", e)
        return self

    def is_at(self):
        if not self.page:
            return False
        return "Login" == self.page.get_title_text()

    def enter_username(self, username):
        try:
            username_input = self.page.get_element_by_id("username")
            username_input.set_text(username)
        except Exception as e:
            logging.error("An error occurred on entering username.", e)
        return self

    def enter_password(self, password):
        try:
            password_input = self.page.get_element_by_id("password")
            password_input.set_text(password)
        except Exception as e:
            logging.error("An error occurred on entering password.", e)
        return self

    def login(self):
        try:
            login_button = self.page.get_element_by_id("loginButton")
            login_button.click()
        except Exception as e:
            logging.error("An error occurred on login.", e)
        return AlbumListPage(self.web_client)

class AlbumListPage:
    def __init__(self, web_client):
        self.web_client = web_client
```
Note that I've used the `htmlunit` library to interact with HTML pages in Python. You'll need to install this library using pip: `pip install htmlunit`. Additionally, I've assumed that you have a constant defined elsewhere called `AUT_PATH`, which seems to be related to the file path of your login page.