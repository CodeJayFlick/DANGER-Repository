import os
from pathlib import Path
from collections import defaultdict

class HelpTopic:
    def __init__(self, help: 'HelpModuleLocation', topic_file: Path):
        self.help = help
        self.topic_file = topic_file
        self.relative_path = topic_file.parent.absolute().relative_to(help.get_help_location())

        self.help_files = defaultdict(dict)

    @classmethod
    def from_html_file(cls, topic_file: Path) -> 'HelpTopic':
        topic = topic_file.parent
        topics_dir = topic.parent
        help_dir = topics_dir.parent

        loc = DirectoryHelpModuleLocation(os.path.join(str(help_dir), ""))
        return cls(loc, topic_file)

    @property
    def topic_file(self):
        return self.topic_file

    def load_help_files(self, dir: Path) -> None:
        matcher = os.fnmatch.compile("*.html")
        try:
            for file in dir.rglob("*"):
                if matcher.match(file.name):
                    rel_path = str(dir.absolute().relative_to(os.getcwd()))
                    help_files[self.relative_path.joinpath(rel_path)] = HelpFile(self.help, file)
        except FileNotFoundError as e:
            print(f"Error loading help files: {dir}")

    def add_help_file(self, rel_path: Path, help_file: 'HelpFile') -> None:
        self.help_files[rel_path] = help_file

    @property
    def all_hrefs(self) -> list:
        if not isinstance(self.topic_file.fs, os):
            return []
        hrefs = []
        for file in self.help_files.values():
            hrefs.extend(file.all_hrefs)
        return hrefs

    @property
    def all_imgs(self) -> list:
        if not isinstance(self.topic_file.fs, os):
            return []
        imgs = []
        for file in self.help_files.values():
            imgs.extend(file.all_imgs)
        return imgs

    @property
    def all_anchor_definitions(self) -> list:
        anchor_defs = []
        for file in self.help_files.values():
            anchor_defs.extend(file.all_anchor_definitions)
        return anchor_defs

    @property
    def help_files(self):
        return dict(self.help_files)

    @property
    def relative_path(self):
        return self.relative_path

    @property
    def help_directory(self) -> 'HelpModuleLocation':
        return self.help

    @property
    def name(self) -> str:
        return self.topic_file.name

    def __lt__(self, other: 'HelpTopic') -> bool:
        return self.topic_file < other.topic_file

    def __str__(self):
        return str(self.topic_file)
