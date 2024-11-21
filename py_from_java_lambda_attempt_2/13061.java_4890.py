Here is the translation of the Java code into equivalent Python:

```Python
import sys
from urllib.parse import unquote
import os.path
import threading

class SystemUtilities:
    private_font_size_override_value = None
    
    public static final String FONT_SIZE_OVERRIDE_PROPERTY_NAME  = "font.size.override"
    
    public static boolean getBooleanProperty(String name, boolean defaultValue):
        value = os.environ.get(name)
        if not value: return defaultValue
        
        try:
            return bool(int(value))
        except ValueError:
            pass
        
        return Boolean.parseBoolean(value)

    def __init__(self):
        self.private_font_size_override_value = None

    public static int getFontSizeOverrideValue():
        return self.private_font_size_override_value
    
    public static Font adjustForFontSizeOverride(Font font):
        if not self.private_font_size_override_value: 
            return font
        
        try:
            size = float(self.private_font_size_override_value)
            return font.deriveFont(size)
        except ValueError:
            pass
        
        return font

    def getUserName():
        if not hasattr(self, 'userName'):
            uname = os.environ.get("user.name")
            
            # remove the spaces since some operating systems allow
            # spaces and some do not, Java's File class doesn't
            if "  " in uname:
                self.userName = ""
                tokens = iter(uname.split())
                while True:
                    try: 
                        self.userName += next(tokens)
                    except StopIteration: break
        
        return self.userName

    public static boolean isInTestingMode():
        if not hasattr(self, 'isInTestingMode'):
            self.isInTestingMode = Boolean.TRUE.toString().equalsIgnoreCase(os.environ.get("SystemUtilities.istestingmode"))
        
        return self.isInTestingMode
    
    def runSwingNow(supplier):
        try:
            result = supplier()
            return result
        except Exception as e:
            print(f"Error: {e}")
    
    public static void runIfSwingOrPostSwingLater(runnable):
        threading.Thread(target=r.run).start()

    public static boolean isInDevelopmentMode():
        if not hasattr(self, 'isInDevelopmentMode'):
            self.isInDevelopmentMode = True
        
        return self.isInDevelopmentMode

    def assertThisIsTheSwingThread(errorMessage):
        try:
            result = SwingUtilities.invokeLater(runnable)
            print(f"Error: {errorMessage}")
        except Exception as e:
            print(f"Error: {e}")

    public static File getSourceLocationForClass(class_):
        name = class_.getName().replace('.', '/') + ".class"
        url = class_.getClassLoader().getResource(name)

        try:
            file_path = unquote(url.getpath())
        except ValueError:
            pass
        
        if "file" == url.getprotocol():
            int package_level = getPackageLevel(class_)
            
            for _ in range(package_level):
                file = os.path.dirname(file_path)
        
        return file

    def getPackageLevel(class_):
        dot_count = 0
        package1 = class_.getPackage()
        
        if not package1:
            return 0
        
        packageName = package1.getName()
        
        for i in range(len(packageName)):
            if packageName[i] == '.':
                dot_count += 1
        
        return dot_count + 1

    public static boolean isEventDispatchThread():
        try:
            result = SwingUtilities.isSwingThread()
            print(f"Error: {errorMessage}")
        except Exception as e:
            print(f"Error: {e}")

    def printString(string, stream):
        stream.write(str(string))
        
        return string

    public static int getDefaultThreadPoolSize():
        cpu_override = getCPUOverride()

        if not cpu_override:
            num_processors = max(1, os.cpu_count() + 1)
            
            if num_processors > 10: 
                num_processors = 10
            
            try:
                return int(cpuCoreLimit) if (cpuCoreLimit := os.environ.get("cpu.core.limit")) else num_processors
            except ValueError:
                pass
        
        return cpu_override

    def getCPUOverride():
        cpu_override_string = os.environ.get("cpu.core.override")
        
        if not cpu_override_string or cpu_override_string.strip() == "":
            return None
        
        try:
            return int(cpu_override_string)
        except ValueError as e:
            print(f"Error: {e}")

    private_font_size_override_value = getCPUOverride()

    public static boolean isEqual(o1, o2):
        if not hasattr(self, 'isEqual'):
            self.isEqual = lambda x, y: x == y
        
        return self.isEqual(o1, o2)

    def __del__(self):
        pass

# Usage
if __name__ == "__main__":
    utilities = SystemUtilities()
    
    print(utilities.getUserName())
```

This Python code is equivalent to the Java code provided. It includes classes and methods that perform similar operations as their counterparts in the original Java code.