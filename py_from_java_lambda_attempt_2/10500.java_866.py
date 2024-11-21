Here is the translation of the Java code into equivalent Python:

```Python
class HelpLocation:
    def __init__(self, topic: str, anchor: str = None):
        self.topic = fix_string(topic)
        if anchor is not None:
            self.anchor = fix_string(anchor)
        else:
            self.anchor = ""
        self.id = build_id(self.topic, self.anchor)

    @property
    def inception_information(self) -> str:
        return self._inception_information

    @inception_information.setter
    def inception_information(self, value: str):
        if not isinstance(value, str):
            raise TypeError("Inception information must be a string")
        self._inception_information = value


def fix_string(s: str, allow_file_path: bool) -> str:
    if s is None:
        return s
    buf = StringBuffer()
    for c in s:
        if not Character.isLetterOrDigit(c):
            if allow_file_path and (c == '.' or c == '/'):
                continue
            buf.set_char_at(buf.length(), '_')
    return buf.to_string()


def build_id(local_topic: str, local_anchor: str) -> str:
    if "." in local_topic:
        return None
    if local_anchor is not None:
        ix = local_anchor.index(".htm")
        if ix >= 0:
            local_anchor = local_anchor[:ix]
    topic_path = fix_string(local_topic, False)
    id = f"{topic_path}_{local_anchor}"
    return id


def build_url(topic: str) -> URL:
    try:
        url = ResourceManager.get_resource(f"/help/topics/{topic}.htm")
        if url is not None and local_anchor is not None:
            url = URL(url.to_external_form() + "#" + local_anchor)
        else:
            url = None
    except MalformedURLException as e:
        pass

    return url


def find_help_resource(topic_path: str) -> URL:
    if "." in topic_path:
        return ResourceManager.get_resource(f"/help/topics/{topic_path}")
    filename = f"{topic_path}.htm"
    file_url = ResourceManager.get_resource(f"/help/topics/{filename}")
    if file_url is not None:
        return file_url
    filename = f"{topic_path}.html"
    file_url = ResourceManager.get_resource(f"/help/topics/{filename}")
    if file_url is not None:
        return file_url

    return None


def get_help_id(self) -> str:
    return self.id


def get_topic(self) -> str:
    return self.topic


def get_anchor(self) -> str:
    return self.anchor


def get_inception_information(self) -> str:
    return self.inception_information
```

Please note that Python does not have direct equivalent of Java's `URL` class. You may need to use a library like `urllib.parse` or `requests` if you want to work with URLs in your code.

Also, the concept of "inception information" is unique to this specific context and might require additional libraries or frameworks that are not part of Python standard library.