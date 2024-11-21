class ImageRoot:
    DEX_CACHES = 'kDexCaches'
    CLASS_ROOTS = 'kClassRoots'
    OOME_WHEN_THROWING_EXCEPTION = 'kOomeWhenThrowingException'
    OOME_WHEN_THROWING_OOME = 'kOomeWhenThrowingOome'
    OOME_WHEN_HANDLING_STACK_OVERFLOW = 'kOomeWhenHandlingStackOverflow'
    NO_CLASS_DEF_FOUND_ERROR = 'kNoClassDefFoundError'
    SPECIAL_ROOTS = 'kSpecialRoots'
    IMAGE_ROOTS_MAX = 'kImageRootsMax'

    @classmethod
    def get_app_image_classloader(cls):
        return cls.SPECIAL_ROOTS

    @classmethod
    def get_boot_image_live_objects(cls):
        return cls.SPECIAL_ROOTS


# Usage:
print(ImageRoot.DEX_CACHES)
print(ImageRoot.get_app_image_classloader())
