Here is the translation of the Java code to Python:

```Python
class Installer:
    F_DROID = ("F-Display", "https://f-droid.org/de/packages/")
    GOOGLE_PLAY = ("Google Play", "https://play.google.com/store/apps/details")
    AMAZON_APPSTORE = ("Amazon Appstore", "https://www.amazon.com/gp/mas/dl/android")
    AURORA_STORE = ("Aurora Store", "https://aurorastore.com")

    def __init__(self, display_name):
        self.display_name = display_name

    @classmethod
    def installer_package_name(cls, context):
        return context.getPackageManager().getInstallerPackageName(context.getPackageName())

    @classmethod
    def from_installer_package_name(cls, installer_package_name):
        if installer_package_name == "org.fdroid.fdroid" or installer_package_name == "org.fdroid.fdroid.privileged":
            return Installer.F_DROID[0]
        elif installer_package_name == "com.android.vending":
            return Installer.GOOGLE_PLAY[0]
        elif installer_package_name == "com.amazon.venezia":
            return Installer.AMAZON_APPSTORE[0]
        elif installer_package_name == "com.aurora.store":
            return Installer.AURORA_STORE[0]
        else:
            return None

    @classmethod
    def from_context(cls, context):
        return cls.from_installer_package_name(context.getPackageManager().getInstallerPackageName(context.getPackageName()))

    def app_store_page_for(self, application):
        if self == Installer.F_DROID:
            url = f"{self.display_name[1]}/{application.getPackageName()}"
        elif self in [Installer.GOOGLE_PLAY, Installer.AURORA_STORE]:
            url = f"{self.display_name[1]}?id={application.getPackageName()}"
        elif self == Installer.AMAZON_APPSTORE:
            url = f"{self.display_name[1]}?p={application.getPackageName()}"
        else:
            raise ValueError(self)
        return url
```

Please note that Python does not have direct equivalent of Java's enum. It has a class, which can be used to achieve similar functionality as an enum in Java.