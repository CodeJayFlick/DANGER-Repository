import os
from collections import defaultdict

class InvalidLink:
    def __init__(self):
        pass


class LinkDatabase:
    def __init__(self):
        self.unresolved_links = []

    def add_unresolved_link(self, link):
        self.unresolved_links.append(link)

    def get_unresolved_links(self):
        return self.unresolved_links

    def resolve_file(self, path):
        # TO DO: implement file resolution logic
        pass


class JavaHelpValidator:
    EXCLUDED_FILE_NAMES = set()

    def __init__(self, module_name, help_module_collection):
        self.module_name = module_name
        self.help_module_collection = help_module_collection

    @staticmethod
    def create_excluded_file_set():
        excluded_file_names = set()
        # The expected format is the help path, without an extension (this helps catch multiple references with anchors)
        excluded_file_names.add("help/topics/Misc/Tips")
        excluded_file_names.add("docs/WhatsNew")
        excluded_file_names.add("docs/README_PDB")

        return excluded_file_names

    def validate_internal_file_links(self):
        self.validate_help_directory_internal_links(self.help_module_collection)

    def validate_help_directory_internal_links(self, help_collection, link_database):
        debug(f"validating internal help links for module: {help_collection}")
        
        unresolved_links = []
        collection_hrefs = help_collection.get_all_hrefs()
        debug(f"\tHREF count: {len(collection_hrefs)}")
        for href in collection_hrefs:
            if not href.is_remote():
                path_reference_file_help_path = href.get_reference_file_help_path()
                help_file = self.help_module_collection.get_help_file(path_reference_file_help_path)
                self.validate_href_help_file(href, help_file, unresolved_links)

    def validate_href_help_file(self, href, help_file, unresolved_links):
        if not help_file:
            if is_excluded_href(href):
                return
            unresolved_links.append(MissingFileInvalidLink(href))
            return

        anchor_name = href.get_anchor_name()
        if not help_file.contains_anchor(anchor_name):
            unresolved_links.append(MissingAnchorInvalidLink(href))

    def validate_img_file(self, img, link_database):
        if img.is_remote():
            return
        elif img.is_runtime():
            # The tool will load this image at runtime--don't perform normal validation (runtime means an icon to be loaded from a Java file)
            if not img.is_invalid():
                return

    def find_path_in_help(self, img):
        path_image_file = img.get_image_file()
        for help_dir in self.help_module_collection.get_help_roots():
            test_path = os.path.join(help_dir, path_image_file)
            if os.path.exists(test_path):
                return test_path
        return None

    def find_path_in_modules(self, img):
        raw_src = img.get_src_attribute()
        module_roots = Application().get_module_root_directories()
        for resource_file in module_roots:
            resource_dir = ResourceFile(resource_file, "src/main/resources")
            path_to_check = os.path.join(resource_dir, raw_src)
            if os.path.exists(path_to_check):
                return path_to_check
        return None

    def make_path(self, dir, img_src):
        if not dir.exists():
            return None
        
        dir_path = os.path.abspath(dir)
        image_file_fs = to_fs(os.path.join(dir_path, img_src))
        to_check = os.path.join(dir_path, image_file_fs)
        if os.path.exists(to_check):
            return to_check
        return None

    def case_matches(self, img, path):
        real_path = self.make_real_path(path)
        if not real_path:
            return False
        
        real_filename = os.path.basename(real_path)
        image_filename = os.path.basename(img.get_image_file())
        
        if real_filename == image_filename:
            return True
        return False

    def remove_redundant_help(self, root, p):
        if p.startswith("help"):
            # this is the 'help system syntax'; may need to chop off 'help'
            if root.endswith("help"):
                p = os.path.dirname(p)
        
        return p

    @staticmethod
    def debug(message):
        print(f"[{JavaHelpValidator.__name__}] {message}")

    def validate_external_file_links(self, link_database):
        unresolved_links = link_database.get_unresolved_links()
        self.debug(f"validating {len(unresolved_links)} unresolved external links")

        for link in unresolved_links:
            if isinstance(link, InvalidHREFLink) and not isinstance(link, MissingAnchorInvalidLink):
                referenced_help_file = link_database.resolve_link(link)
                if referenced_help_file:
                    continue
                break

    def validate_external_image_file_links(self, link_database):
        unresolved_links = link_database.get_unresolved_links()
        self.debug(f"validating {len(unresolved_links)} unresolved external image links")

        for link in unresolved_links:
            if isinstance(link, NonExistentIMGFileInvalidLink):
                continue
            break

    def validate_toc_item_ids(self, link_database):
        debug("Validating TOC item IDs...")
        
        unresolved_links = []
        collection_items = self.help_module_collection.get_input_toc_items()

        for item in collection_items:
            if not item.validate(link_database):
                if isinstance(item, TOCItemReference):
                    unresolved_links.append(MissingTOCTargetIDInvalidLink(self.help_module_collection, item))
                else:
                    target_path = item.get_target_attribute()
                    if not is_excluded_path(target_path):
                        unresolved_links.append(MissingTOCTargetIDInvalidLink(self.help_module_collection, item))

    def validate(self, link_database):
        self.validate_internal_file_links(link_database)
        
        self.validate_external_file_links(link_database)
        self.validate_external_image_file_links(link_database)

        self.validate_toc_item_ids(link_database)

        return link_database.get_unresolved_links()


class ResourceFile:
    def __init__(self, root_dir, path):
        self.root_dir = os.path.abspath(root_dir)
        self.path = path

    @property
    def exists(self):
        return os.path.exists(os.path.join(self.root_dir, self.path))


def to_fs(dir_path, img_src):
    image_file_fs = os.path.relpath(img_src, dir_path)
    if not image_file_fs.startswith("help"):
        image_file_fs = "help/" + image_file_fs
    return image_file_fs


class MissingFileInvalidLink(InvalidLink):
    def __init__(self, href):
        self.href = href

    @property
    def message(self):
        return f"Missing file: {self.href}"


class InvalidHREFLink:
    pass


def is_excluded_href(href):
    path = href.get_ref_string()
    if path.startswith("/docs/api/"):
        # exclude all api files
        return True

    index = path.rfind(".")
    if index != -1:
        path = path[:index]
    
    return JavaHelpValidator.EXCLUDED_FILE_NAMES.issuperset({path})


class TOCItemReference:
    pass


def is_excluded_path(path):
    # strip off the extension
    index = path.rfind(".")
    if index != -1:
        path = path[:index]

    return JavaHelpValidator.EXCLUDED_FILE_NAMES.issuperset({path})
