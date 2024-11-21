import unittest
from urllib.parse import urlparse, urlunparse, quote

class UriBuilder:
    def __init__(self, base_url):
        self.base_url = base_url
        self.path_parts = []
        self.query_params = {}

    def path(self, *parts):
        for part in parts:
            if isinstance(part, str) and '{' in part:
                raise ValueError("Path template not supported")
            self.path_parts.append(quote(str(part)))

    def resolve_template(self, name, value):
        return f"{self.base_url}{'' if len(self.path_parts) == 0 else '/'}{'/'.join(self.path_parts)}{f"/{value}" if value is not None and '' in self.path_parts else ''}"

    def query_param(self, key, value=None):
        if value:
            self.query_params[key] = str(value)
        return self

    def build(self):
        path = '/'.join(self.path_parts) if len(self.path_parts) > 0 else ''
        query_string = '&'.join(f"{key}={value}" for key, value in self.query_params.items()) if len(self.query_params) > 0 else ''

        return urlunparse((self.base_url.netloc, self.base_url.port, path, '', query_string, ''))

class TestUriBuilder(unittest.TestCase):
    def test_simple(self):
        builder = UriBuilder(URI("http://localhost/"))
        self.assertEqual(builder.build(), "http://localhost/")

    def test_parameter_validation(self):
        with self.assertRaises(ValueError):
            UriBuilder(None)

        with self.assertRaises(ValueError):
            UriBuilder(URI("http://base/")).path(None)

        with self.assertRaises(ValueError):
            UriBuilder(URI("http://base/")).resolve_template(None, "value")

        with self.assertRaises(ValueError):
            UriBuilder(URI("http://base/")).resolve_template("name", None)

    def test_add_missing_slash(self):
        builder = UriBuilder(URI("http://localhost"))
        self.assertEqual(builder.build(), "http://localhost/")
        self.assertEqual(UriBuilder(URI("http://localhost")).path("foo").path("bar").build(), "http://localhost/foo/bar")

    def test_path_templates(self):
        builder = UriBuilder(URI("http://localhost/"))

        builder.path("{my-var}").resolve_template("my-var", "baz")
        self.assertEqual(builder.build(), "http://localhost/baz")

        builder.path("something/{in}/here").resolve_template("in", "out")
        self.assertEqual(builder.build(), "http://localhost/baz/something/out/here")

        with self.assertRaises(ValueError):
            UriBuilder(URI("http://base/")).build()

    def test_path_encoding(self):
        builder = UriBuilder(URI("http://localhost/"))

        builder.path("some spaces in here")
        self.assertEqual(builder.build(), "http://localhost/some%20spaces%20in%20here")

    def test_query_parameters(self):
        builder = UriBuilder(URI("http://localhost/"))

        builder.query_param("a", "b")
        self.assertEqual(builder.build(), "http://localhost/?a=b")

        builder.query_param("c", "d")
        self.assertEqual(builder.build(), "http://localhost/?a=b&c=d")

        builder.query_param("e", "f&? /")
        self.assertEqual(builder.build(), "http://localhost/?a=b&c=d&e=f%26%3F%20/")

        builder.query_param("c", "d-more")
        self.assertEqual(builder.build(), "http://localhost/?a=b&c=d&e=f%26%3F%20/&c=d-more")


if __name__ == '__main__':
    unittest.main()
