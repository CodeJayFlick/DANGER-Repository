class ImageRoot:
    """Enum for Android ART image roots"""
    
    class Enum:
        kDexCaches = 1
        kClassRoots = 2
        kSpecialRoots = 3
        kImageRootsMax = 4

# Aliases
kAppImageClassLoader = ImageRoot.kSpecialRoots
kBootImageLiveObjects = ImageRoot.kSpecialRoots
