import logging
from urllib.parse import urlparse
from os.path import join, exists
from glob import glob

class TriggerClassLoader:
    def __init__(self, lib_root):
        self.lib_root = lib_root
        self.logger = logging.getLogger(__name__)
        self.logger.info("Trigger lib root: %s", lib_root)
        self.add_urls()

    def add_urls(self):
        file_set = set(glob(join(self.lib_root, "*")))
        urls = [urlparse(file).geturl() for file in file_set]
        for url in urls:
            yield from self._add_url(url)

    async def _add_url(self, url):
        try:
            await super().__init__(self)
            self.logger.info("Added URL: %s", url)
        except Exception as e:
            self.logger.error("Error adding URL: %s", str(e))
