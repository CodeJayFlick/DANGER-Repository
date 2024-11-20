class ImageManager:
    COPY = None
    CUT = None
    DELETE = None
    FONT = None
    LOCKED = None
    NEW = None
    PASTE = None
    REDO = None
    RENAME = None
    REFRESH = None
    SAVE = None
    SAVE_AS = None
    UNDO = None
    UNLOCKED = None
    CLOSE = None
    COLLAPSE_ALL = None
    COMPRESS = None
    CREATE_FIRMWARE = None
    EXPAND_ALL = None
    EXTRACT = None
    INFO = None
    OPEN = None
    OPEN_AS_BINARY = None
    OPEN_IN_LISTING = None
    OPEN_FILE_SYSTEM = None
    PHOTO = None
    VIEW_AS_IMAGE = None
    VIEW_AS_TEXT = None
    UNKNOWN = None
    IPOD = None
    IPOD_48 = None
    ECLIPSE = None
    JAR = None
    KEY = None
    IMPORT = None
    iOS = None
    OPEN_ALL = None
    LIST_MOUNTED = None

    def __init__(self):
        from resources import Icons, ResourceManager

        self.COPY = ResourceManager.load_image("images/page_copy.png")
        self.CUT = ResourceManager.load_image("images/edit-cut.png")
        self.DELETE = ResourceManager.load_image("images/page_delete.png")
        self.FONT = ResourceManager.load_image("images/text_lowercase.png")
        self.LOCKED = ResourceManager.load_image("images/lock.gif")
        self.NEW = ResourceManager.load_image("images/page_add.png")
        self.PASTE = ResourceManager.load_image("images/page_paste.png")
        self.REDO = Icons.REFRESH_ICON
        self.RENAME = ResourceManager.load_image("images/textfield_rename.png")
        self.REFRESH = Icons.REFRESH_ICON
        self.SAVE = ResourceManager.load_image("images/disk.png")
        self.SAVE_AS = ResourceManager.load_image("images/disk_save_as.png")
        self.UNDO = ResourceManager.load_image("images/undo.png")
        self.UNLOCKED = ResourceManager.load_image("images/unlock.gif")
        self.CLOSE = ResourceManager.load_image("images/famfamfam_silk_icons_v013/door.png")
        self.COLLAPSE_ALL = ResourceManager.load_image("images/famfamfam_silk_icons_v013/arrow_in.png")
        self.COMPRESS = ResourceManager.load_image("images/famfamfam_silk_icons_v013/compress.png")
        self.CREATE_FIRMWARE = ResourceManager.load_image("images/media-flash.png")
        self.EXPAND_ALL = ResourceManager.load_image("images/famfamfam_silk_icons_v013/arrow_inout.png")
        self.EXTRACT = ResourceManager.load_image("images/package_green.png")
        self.INFO = ResourceManager.load_image("images/famfamfam_silk_icons_v013/information.png")
        self.OPEN = ResourceManager.load_image("images/famfamfam_silk_icons_v013/door_open.png")
        self.OPEN_AS_BINARY = ResourceManager.load_image("images/famfamfam_silk_icons_v013/controller.png")
        self.OPEN_IN_LISTING = ResourceManager.load_image("images/famfamfam_silk_icons_v013/folder_table.png")
        self.OPEN_FILE_SYSTEM = ResourceManager.load_image("images/famfamfam_silk_icons_v013/folder_brick.png")
        self.PHOTO = ResourceManager.load_image("images/famfamfam_silk_icons_v013/photo.png")
        self.VIEW_AS_IMAGE = ResourceManager.load_image("images/oxygen/16x16/games-config-background.png")
        self.VIEW_AS_TEXT = ResourceManager.load_image("images/format-text-bold.png")
        self.UNKNOWN = ResourceManager.load_image("images/help-browser.png")
        self.IPOD = ResourceManager.load_image("images/famfamfam_silk_icons_v013/ipod.png")
        self.IPOD_48 = ResourceManager.load_image("images/oxygen/48x48/multimedia-player-apple-ipod.png")
        self.ECLIPSE = ResourceManager.load_image("images/eclipse.png")
        self.JAR = ResourceManager.load_image("images/famfamfam_silk_icons_v013/page_white_cup.png")
        self.KEY = ResourceManager.load_image("images/famfamfam_silk_icons_v013/application_key.png")
        self.IMPORT = ResourceManager.load_image("images/famfamfam_silk_icons_v013/application_get.png")
        self.iOS = ResourceManager.load_image("images/famfamfam_silk_icons_v013/phone.png")
        self.OPEN_ALL = ResourceManager.load_image("images/famfamfam_silk_icons_v013/application_cascade.png")
        self.LIST_MOUNTED = ResourceManager.load_image("images/downArrow.png")

    def __str__(self):
        return "ImageManager"
