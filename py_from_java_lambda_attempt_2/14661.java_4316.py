Here is the translation of the Java code to Python:

```Python
class LoginPage:
    def __init__(self):
        self.page = None

    def navigate_to_page(self):
        try:
            from bs4 import BeautifulSoup as Soup
            import requests
            response = requests.get("file:login.html")
            self.page = Soup(response.text, 'html.parser')
        except Exception as e:
            print(e)

        return self

    def is_at(self):
        if "Login" == str(self.page.title):
            return True
        else:
            return False


    def enter_username(self, username):
        try:
            from bs4 import BeautifulSoup as Soup
            input_field = self.page.find("input", {"id": "username"})
            input_field["value"] = username
        except Exception as e:
            print(e)

        return self

    def enter_password(self, password):
        try:
            from bs4 import BeautifulSoup as Soup
            input_field = self.page.find("input", {"id": "password"})
            input_field["value"] = password
        except Exception as e:
            print(e)

        return self


    def login(self):
        try:
            from bs4 import BeautifulSoup as Soup
            button = self.page.find("button", {"id": "loginButton"})
            if button is not None:
                button.click()
        except Exception as e:
            print(e)

        # Assuming AlbumListPage class exists in the same file or imported correctly.
        return AlbumListPage()

class AlbumListPage:
    def __init__(self):
        pass
```

Please note that Python does not have direct equivalent of Java's `WebClient` and `HtmlUnit`. This code uses `requests` library to load HTML content, and `BeautifulSoup` for parsing the HTML.