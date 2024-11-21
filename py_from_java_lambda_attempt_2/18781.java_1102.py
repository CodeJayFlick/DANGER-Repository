Here is the translation of the Java code to Python:

```Python
import urllib.parse
from urllib.error import URLError

class UriBuilder:
    def __init__(self, base_uri):
        self.base_uri = base_uri
        self.uri = ''
        self.query = ''
        self.template_values = {}

    def path(self, path):
        if self.uri:
            self.uri += '/'
        trimmed_path = urllib.parse.quote(path)
        if not trimmed_path:
            raise ValueError("Path must be of length greater than 0")
        self.uri += trimmed_path
        return self

    def query_param(self, name, value):
        if not value:
            return self
        if self.query:
            self.query += '&'
        self.query += urllib.parse.quote(name) + '=' + urllib.parse.quote(value)
        return self

    def resolve_template(self, name, value):
        self.template_values[urllib.parse.quote(name)] = urllib.parse.quote(value)
        return self

    @staticmethod
    def check_empty(templates, uri):
        if templates:
            keys = ';'.join(sorted(templates.keys()))
            raise ValueError(f"Cannot build uri. Not all template keys ({keys}) were used in uri {uri}")

    def build(self) -> str:
        builder = urllib.parse.urlunparse((self.base_uri.scheme, self.base_uri.netloc, '', '', self.query, ''))
        if not builder.endswith('/'):
            builder += '/'
        for part in self.uri.split('/'):
            if part in self.template_values:
                value = self.template_values.pop(part)
                builder += '/' + urllib.parse.quote(value)
            else:
                builder += '/' + urllib.parse.quote(part)
        if self.query:
            builder += '?' + self.query
        return builder

    @staticmethod
    def encode(s):
        try:
            return urllib.parse.quote_plus(s).replace('+', '%20')
        except URLError as e:
            raise ValueError(f"Cannot url encode {s}", e)

# Example usage:
base_uri = 'https://example.com'
builder = UriBuilder(base_uri)
uri_builder = builder.path('path').query_param('name', 'value').resolve_template('template_name', 'template_value')
print(uri_builder.build())
```

Note that Python's `urllib.parse` module is used for URL encoding and decoding, which replaces the Java code. The `UriBuilder` class in this translation does not have a direct equivalent to the Java method `checkEmpty`, as it would be better handled by raising an exception when building the URI if there are any unused template values.