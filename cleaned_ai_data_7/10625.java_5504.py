import os
from urllib.parse import urlparse
from collections import defaultdict

class ResourceManager:
    DEFAULT_ICON_FILENAME = 'BOMB'
    icon_map = defaultdict(lambda: None)
    default_search_paths = []
    test_search_paths = []

    @classmethod
    def get_resource(cls, filename):
        url = cls.class_loader.get_resource(filename)
        if url is not None:
            return url
        for path in cls.test_search_paths or []:
            f = os.path.join(path, filename)
            if os.path.exists(f):
                try:
                    return urlparse('file://' + f).geturl()
                except ValueError as e:
                    Msg.error(cls.__class__, 'Unable to create URL for file', e)
        return None

    @classmethod
    def get_resource_stream(cls, filename):
        stream = cls.class_loader.get_resourceAsStream(filename)
        if stream is not None:
            return stream
        url = cls.get_resource(filename)
        if url is None:
            return None
        try:
            return urllib.request.urlopen(url).stream()
        except IOException as e:
            Msg.error(cls.__class__, 'Unable to open input stream for', e)

    @classmethod
    def get_default_icon(cls):
        if not hasattr(cls, '_default_icon'):
            cls._default_icon = cls.get_image_icon(ResourceManager.DEFAULT_ICON_FILENAME)
        return getattr(cls, '_default_icon')

    # ... other methods ...

if __name__ == '__main__':
    class_loader = ResourceManager.__class__.getClass().getClassLoader()
