import urllib.request


class Icons:
    EMPTY_ICON = get_icon("images/EmptyIcon16.gif")
    HELP_ICON = get_icon("images/help-browser.png")
    ADD_ICON = get_icon("images/Plus2.png")
    COLLAPSE_ALL_ICON = get_icon("images/collapse_all.png")
    EXPAND_ALL_ICON = get_icon("images/expand_all.png")

    CONFIGURE_FILTER_ICON = get_icon("images/exec.png")
    DELETE_ICON = get_icon("images/error.png")
    ERROR_ICON = get_icon("images/emblem-important.png")

    NAVIGATE_ON_INCOMING_EVENT_ICON = get_icon("images/locationIn.gif")
    NAVIGATE_ON_OUTGOING_EVENT_ICON = get_icon("images/locationOut.gif")

    NOT_ALLOWED_ICON = get_icon("images/no.png")
    OPEN_FOLDER_ICON = get_icon("images/openSmallFolder.png")
    REFRESH_ICON = get_icon("images/reload3.png")

    SORT_ASCENDING_ICON = get_icon("images/sortascending.png")
    SORT_DESCENDING_ICON = get_icon("images/sortdescending.png")

    STOP_ICON = get_icon("images/process-stop.png")
    STRONG_WARNING_ICON = get_icon("images/software-update-urgent.png")

    LEFT_ICON = get_icon("images/left.png")
    RIGHT_ICON = get_icon("images/right.png")

    LEFT_ALTERNATE_ICON = get_icon("images/left.alternate.png")
    RIGHT_ALTERNATE_ICON = get_icon("images/right.alternate.png")

    SAVE_AS = ResourceManager.get_image_icon(DotDotDotIcon(get_icon("images/Disk.png")))

    MAKE_SELECTION_ICON = get_icon("images/text_align_justify.png")

    ARROW_DOWN_RIGHT_ICON = ResourceManager.get_image_icon(RotateIcon(get_icon("images/viewmagfit.png"), 90))
    ARROW_UP_LEFT_ICON = ResourceManager.get_image_icon(RotateIcon(get_icon("images/viewmagfit.png"), 275))

    FILTER_NOT_ACCEPTED_ICON = ResourceManager.get_image_icon(MultiIcon(get_icon("images/flag.png"),
                                                                         TranslateIcon(ResourceManager.load_image("images/dialog-cancel.png", 10, 10), 6, 6)))

    APPLY_BLOCKED_MATCH_ICON = ResourceManager.get_image_icon(
        MultiIcon(get_icon("images/kgpg.png"), TranslateIcon(ResourceManager.load_image("images/checkmark_green.gif", 12, 12), 4, 0)))


def is_icons_reference(snippet):
    return snippet.startswith(Icons.__name__)


def get_icon_for_icons_reference(snippet):
    field_name = get_icon_name(snippet)
    if field_name is None:
        return None

    icon = get_icon_by_field_name(field_name)
    if icon is None:
        return None

    url = urllib.request.url2pathname(get_url_from_icon(icon))
    return IconProvider(icon, url)


def get_icon(icon_path):
    return ResourceManager.load_image(icon_path)


def get_icon(icon_path, width, height):
    return ResourceManager.load_image(icon_path, width, height)


def get_icon_name(snippet):
    if not is_icons_reference(snippet):
        return None

    field_name = snippet[len(Icons.__name__) + 1:]
    return field_name


def get_icon_by_field_name(field_name):
    try:
        icon = Icons().__dict__[field_name]
        return icon
    except Exception as e:
        Msg.debug(Icons, f"No icon named '{field_name}' in class {Icons.__name__}")
        return None


def get_url_from_icon(icon):
    if icon is None:
        return None

    description = icon.get_description()
    if description is None:
        Msg.debug(Icons, "Unable to get URL for icon - icon description is missing")
        return None

    try:
        url = urllib.request.url2pathname(description)
        return url
    except Exception as e:
        Msg.trace(Icons, f"Unable to get URL for icon: {description}")
        return None


class DotDotDotIcon(Icon):
    def __init__(self, base_icon):
        self.base = ResourceManager.get_scaled_icon(base_icon, 12, 12)

    def paint_icon(self, c, g, x, y):
        self.base.paint_icon(c, g, x, y)
        g.set_color(Color(50, 50, 50))
        g.fill_rect(x + 6, y + 14, 2, 2)
        g.fill_rect(x + 9, y + 14, 2, 2)
        g.fill_rect(x + 12, y + 14, 2, 2)

    def get_icon_width(self):
        return 16

    def get_icon_height(self):
        return 16


class IconProvider:
    def __init__(self, icon, url):
        self.icon = icon
        self.url = url
