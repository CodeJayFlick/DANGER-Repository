import logging
from urllib.parse import urlparse

class GHelpSet:
    HOME_ID = "Misc_Welcome_to_Ghidra_Help"

    help_sets_to_combined_maps = {}
    help_setsToLocalMaps = {}

    def __init__(self, loader, url):
        super().__init__(loader, url)
        self.init()

    def init(self):
        # swap in Ghidra's editor kit
        type = "text/html"
        editor_kit = GHelpHTMLEditorKit.__name__
        class_loader = self.__class__.__loader__

        set_key_data(kit_type_registry, type, editor_kit)
        set_key_data(kit_loader_registry, type, class_loader)

        self.set_home_id(HOME_ID)

        initialize_combined_map_wrapper()
        initialize_local_map_wrapper()

    def create_help_broker(self):
        return GHelpBroker(self)

    def get_local_map(self):
        local_map = super().get_local_map()
        if local_map is None:
            return None

        initialize_local_map_wrapper()
        return self.local_map_wrapper

    def get_combined_map(self):
        return self.combined_map_wrapper


class GHelpMap(dict):
    def __init__(self, map_delegate):
        self.map_delegate = map_delegate

    def get_all_ids(self):
        return self.map_delegate.get_all_ids()

    def get_closest_id(self, url):
        closest_id = self.map_delegate.get_closest_id(url)
        if closest_id is not None:
            return closest_id  # it's in our map
        else:
            for entry in help_sets_to_combined_maps.items():
                map_ = entry[1]
                closest_id = map_.get_closest_id(url)
                if closest_id is not None:
                    return closest_id

            logging.trace("No ID found in any HelpSet for URL: " + str(url))
            return None


    def get_id_from_url(self, url):
        return self.map_delegate.get_id_from_url(url)

    def get_ids(self, url):
        return self.map_delegate.get_ids(url)


def initialize_local_map_wrapper():
    if local_map_wrapper is None:
        map_ = super().get_local_map()
        help_setsToLocalMaps[self] = map_
        global local_map_wrapper
        local_map_wrapper = GHelpMap(map_)
        pass


def initialize_combined_map_wrapper():
    if combined_map_wrapper is None:
        map_ = super().get_combined_map()
        help_sets_to_combined_maps[self] = map_
        global combined_map_wrapper
        combined_map_wrapper = GHelpMap(map_)
        pass


class ResourceFile:
    def __init__(self, install_dir, id):
        self.install_dir = install_dir
        self.id = id

    @property
    def to_url(self):
        return urlparse.urljoin(str(self.install_dir), str(self.id))


def file_from_id(id):
    # this allows us to find files by using relative paths (e.g., 'docs/WhatsNew.html'
    # will get resolved relative to the installation directory in a build).
    install_dir = Application.get_installation_directory()
    help_file = ResourceFile(install_dir, id)
    return help_file


def try_to_create_url_from_id(id):
    file_url = create_file_url(id)
    if file_url is not None:
        return file_url

    raw_url = create_raw_url(id)
    return raw_url


def create_raw_url(id):
    url = urlparse.urlparse(id)
    if url.scheme and url.netloc:
        try:
            input_stream = url.open()
            input_stream.close()
            return url
        except IOError as e:
            logging.trace("ID is not a URL; unable to read URL: " + str(url))
    else:
        try:
            return urlparse.urlunparse((url.scheme, url.netloc, id, '', '', ''))
        except ValueError as e:
            pass

    return None


def create_file_url(id):
    help_file = file_from_id(id)
    if not help_file.exists():
        logging.trace("ID is not a file; tried: " + str(help_file))
        return None
    else:
        try:
            return help_file.to_url()
        except ValueError as e:
            pass

    return None


def ignore_external_help(id):
    if id.startswith("help/topics"):
        return False  # not external help location

    url = try_to_create_url_from_id(id)
    if url is not None:
        return True  # ignore this ID; it's valid
    else:
        if SystemUtilities.is_in_development_mode():
            return True  # ignore external files that do not exist in dev mode
        else:
            return False

# Initialize the help sets to combined maps and local maps.
help_sets_to_combined_maps = {}
help_setsToLocalMaps = {}

combined_map_wrapper = None
local_map_wrapper = None


class GHelpBroker:
    def __init__(self, g_help_set):
        self.g_help_set = g_help_set

    # Your code here...
