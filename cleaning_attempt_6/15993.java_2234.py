import os
import shutil
import gzip
import requests
from urllib.parse import urlparse
from io import BytesIO
from zipfile import ZipFile
from packaging.version import Version

class LibUtils:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    @staticmethod
    def load_library():
        lib_name = find_override_library()
        if not lib_name:
            lib_name = find_library_in_classpath(AtomicBoolean(False))
            if not lib_name:
                raise Exception("Native library not found")
        
        if os.name.startswith('linux'):
            LibUtils.load_linux_dependencies(lib_name)
        elif os.name.startswith('win'):
            LibUtils.load_windows_dependencies(lib_name)

        self.logger.debug(f"Now loading {lib_name}")
        try:
            _ = ctypes.CDLL(lib_name)  # Load the library
        except Exception as e:
            raise Exception("Failed to load native library") from e

    @staticmethod
    def load_linux_dependencies(lib_name):
        lib_dir = os.path.dirname(lib_name)
        if lib_dir:
            self.logger.info(f"Paddle MKL/GPU requires user to set LD_LIBRARY_PATH={lib_dir}, the current one is set to: {os.environ.get('LD_LIBRARY_ PATH')}")
            libraries = ['libdnnl.so.2', 'libiomp5.so', 'libmklml_intel.so']
            for lib in libraries:
                path = os.path.join(lib_dir, lib)
                if os.path.exists(path):
                    self.logger.debug(f"Now loading {path}")
                    try:
                        _ = ctypes.CDLL(path)  # Load the library
                    except Exception as e:
                        self.logger.warning(f"{lib} is not found, skip loading...")
                else:
                    self.logger.debug(f"{lib} is not found, skip loading...")

    @staticmethod
    def load_windows_dependencies(lib_name):
        lib_dir = os.path.dirname(lib_name)
        libraries = ['openblas.dll']
        for lib in libraries:
            path = os.path.join(lib_dir, lib)
            if os.path.exists(path):
                self.logger.debug(f"Now loading {path}")
                try:
                    _ = ctypes.CDLL(path)  # Load the library
                except Exception as e:
                    pass

    @staticmethod
    def find_override_library():
        lib_path = os.environ.get('PADDLE_LIBRARY_PATH')
        if lib_path:
            return find_library_in_path(lib_path)
        
        lib_path = sys.meta_path[0]
        if lib_path:
            return find_library_in_path(lib_path)

        return None

    @staticmethod
    def copy_jni_library_from_classpath(native_dir, fallback):
        name = ctypes.util.find_library('paddle_ inference')
        platform = Platform.from_system()
        classifier = platform.get_classifier()
        flavor = platform.get_flavor()
        if fallback:
            flavor = 'cpu'
        
        properties = {}
        try:
            with open(os.path.join(__file__.directory, "jnilib/paddlepaddle.properties")) as f:
                for line in f:
                    key, value = line.strip().split('=')
                    properties[key] = value
        except Exception as e:
            raise Exception("Cannot find paddle property file") from e
        
        version = properties.get('version')
        path = os.path.join(native_dir, version + '-' + flavor + '-' + name)
        if os.path.exists(path):
            return path

        tmp_path = None
        try:
            with open(os.path.join(__file__.directory, "jnilib/paddlepaddle.properties")) as f:
                for line in f:
                    key, value = line.strip().split('=')
                    properties[key] = value
            
            platform = Platform.from_system()
            classifier = platform.get_classifier()
            flavor = platform.get_flavor()
            
            if fallback:
                flavor = 'cpu'
            
            tmp_path = tempfile.TemporaryDirectory()
            for file in platform.get_libraries():
                lib_path = os.path.join(__file__.directory, "jnilib", file)
                with open(lib_path) as f:
                    content = f.read()
                
                try:
                    with gzip.open(os.path.join(tmp_path.name, file), 'wt') as fo:
                        fo.write(content)
                except Exception as e:
                    raise Exception("Failed to extract PaddlePaddle native library") from e
            
            shutil.move(tmp_path.name, os.path.dirname(path))
        finally:
            if tmp_path is not None:
                try:
                    shutil.rmtree(tmp_path.name)
                except Exception as e:
                    pass
        
        return path

    @staticmethod
    def find_library_in_classpath(fallback):
        urls = []
        for loader in sys.meta_path[0].get_urls():
            urls.extend(loader.get_resources())
        
        if not urls:
            platform = Platform.from_system()
            try:
                with open(os.path.join(__file__.directory, "jnilib/paddlepaddle.properties")) as f:
                    properties = {}
                    for line in f:
                        key, value = line.strip().split('=')
                        properties[key] = value
            
                    return download_library(platform, fallback)
            except Exception as e:
                raise Exception("Failed to read PaddlePaddle native library jar properties") from e
        
        platform_system = None
        placeholder = None
        for url in urls:
            if not os.path.exists(url):
                continue
            
            try:
                with open(os.path.join(__file__.directory, "jnilib/paddlepaddle.properties")) as f:
                    properties = {}
                    for line in f:
                        key, value = line.strip().split('=')
                        properties[key] = value
                
                    platform = Platform.from_url(url)
                    if not platform.is_placeholder():
                        return load_library_from_classpath(platform)
            except Exception as e:
                raise Exception("Failed to read PaddlePaddle native library jar properties") from e
        
        if placeholder is None and os.path.exists(placeholder):
            return download_library(placeholder, fallback)

    @staticmethod
    def find_library_in_path(lib_path):
        paths = lib_path.split(os.sep)
        mapped_lib_names = ctypes.util.find_library('paddle_ inference')
        
        for path in paths:
            file_path = os.path.join(path, mapped_lib_names)
            if not os.path.exists(file_path) and os.path.isfile(file_path):
                return file_path
        
        return None

    @staticmethod
    def download_library(platform, fallback):
        version = platform.get_version()
        flavor = platform.get_flavor()
        classifier = platform.get_classifier()
        
        lib_name = ctypes.util.find_library('paddle_ inference')
        cache_dir = os.path.join(os.getcwd(), 'cache', f'{version}-{flavor}-{classifier}')
        path = os.path.join(cache_dir, lib_name)
        if os.path.exists(path):
            return path
        
        matcher = re.compile(r'(\d+\.\d+\.?\d*)').match(version)
        
        link = f'https://publish.djl.ai/paddlepaddle-{matcher.group(1)}'
        try:
            with requests.get(link, stream=True) as response:
                if not os.path.exists(cache_dir):
                    os.makedirs(cache_dir)

                tmp_path = tempfile.TemporaryDirectory()
                for line in response.iter_lines():
                    if line.startswith(f'{flavor}/{os.name}/'):
                        lib_name = line.strip().split('/')[-1]
                        try:
                            with gzip.open(os.path.join(tmp_path.name, lib_name), 'wt') as fo:
                                fo.write(response.content)
                        except Exception as e:
                            raise Exception("Failed to download PaddlePaddle native library") from e
                
                shutil.move(tmp_path.name, cache_dir)
        finally:
            if tmp_path is not None:
                try:
                    shutil.rmtree(tmp_path.name)
                except Exception as e:
                    pass
        
        return path
