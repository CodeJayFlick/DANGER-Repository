Here is the translation of the given Java code into equivalent Python:

```Python
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
```

Please note that Python does not have a direct equivalent to Java's enum. The above code uses classes and class variables to achieve similar functionality.