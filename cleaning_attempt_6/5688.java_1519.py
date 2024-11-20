import os
from datetime import datetime as dt
from functools import lru_cache

class FSUtilities:
    SEPARATOR_CHARS = "/\\:"
    DOT = "."
    
    @lru_cache(maxsize=None)
    def hexdigit(c):
        return c.to_bytes(1, 'big').decode('utf-8')

    GFILE_NAME_TYPE_COMPARATOR = lambda o1, o2: (not o1.is_directory(),) + tuple(o1.name().lower() != o2.name().lower())

    @staticmethod
    def info_map_to_string(info):
        sb = StringBuilder()
        for entry in info.items():
            sb.append(f"{entry[0]}:{entry[1]}\n")
        return str(sb)

    @staticmethod
    def get_safe_filename(untrusted_filename):
        untrusted_filename = re.sub(r'[/\\:|]', '_', untrusted_filename).strip()
        if not untrusted_filename:
            return "empty_filename"
        elif untrusted_filename == ".":
            return "dot"
        elif untrusted_filename == "..":
            return "dotdot"
        else:
            return escape_encode(untrusted_filename)

    @staticmethod
    def escape_encode(s):
        bytes = None
        sb = StringBuilder()
        for i in range(len(s)):
            c = s[i]
            if c < 0x80 or SEPARATOR_CHARS.find(c) >= 0:
                sb.append(c)
            else:
                if not bytes:
                    bytes = bytearray((s[i+1:i+3].encode('utf-8')))
                while i + 2 < len(s):
                    v = int.from_bytes(bytes, 'big')
                    sb.append(f"%{v:02x}")
                    i += 3
        return str(sb)

    @staticmethod
    def escape_decode(s):
        bytes = None
        sb = StringBuilder()
        for i in range(len(s)):
            c = s[i]
            if c == '%':
                while (i + 2 < len(s)) and ((s[i+1:i+3].encode('utf-8'))[0] != 'x'):
                    v = int.from_bytes((s[i+1:i+3].encode('utf-8')), 'big')
                    sb.append(chr(v))
                    i += 3
                if (i + 2 < len(s)) and ((s[i+1:i+3].encode('utf-8'))[0] == 'x'):
                    v = int.from_bytes((s[i+1:i+5].encode('utf-8')), 'big')
                    sb.append(chr(v))
                    i += 4
            else:
                if c < 0x80 or SEPARATOR_CHARS.find(c) >= 0:
                    sb.append(c)
        return str(sb)

    @staticmethod
    def list_file_system(fs, dir, result, task_monitor):
        for gfile in fs.get_listing(dir):
            task_monitor.check_canceled()
            if gfile.is_directory():
                FSUtilities.list_file_system(fs, gfile, result, task_monitor)
            else:
                result.append(gfile)

    @staticmethod
    def get_filesystem_type_from_class(clazz):
        fsi = clazz.__dict__.get('FileSystemInfo')
        return fsi.type() if fsi is not None else None

    @staticmethod
    def get_filesystem_description_from_class(clazz):
        fsi = clazz.__dict__.get('FileSystemInfo')
        return fsi.description() if fsi is not None else None

    @staticmethod
    def get_filesystem_priority_from_class(clazz):
        fsi = clazz.__dict__.get('FileSystemInfo')
        return fsi.priority() if fsi is not None else FileSystemInfo.PRIORITY_DEFAULT

    @staticmethod
    def display_exception(originator, parent, title, message, throwable):
        if isinstance(throwable, CryptoException):
            FSUtilities.display_crypto_exception(originator, parent, title, message, throwable)
        else:
            Msg.show_error(originator, parent, title, f"{message}: {str(throwable)}")

    @staticmethod
    def display_crypto_exception(originator, parent, title, message, ce):
        if "Install the JCE" in str(ce):
            java_home_dir = os.path.join(os.environ['java.home'], 'lib', 'security')
            lib_security_dir = os.path.join(java_home_dir, '')
            OptionDialog.show_yes_no_dialog(parent, f"{title} - {message}", 
                f"A problem with the Java crypto subsystem was encountered: " + str(ce) +
                "\n\nWhich caused:\n" + message + 
                "\n\nThis may be fixed by installing the unlimited strength JCE into your JRE's 'lib/security' directory." + 
                "\nThe unlimited strength JCE should be available from the same download location as your JRE.\nDisplay your JRE's 'lib/security' directory?")
            if OptionDialog.YES_OPTION == 1:
                try:
                    os.startfile(lib_security_dir)
                except Exception as e:
                    Msg.show_error(originator, parent, "Problem starting explorer", str(e))
        else:
            Msg.show_warn(originator, parent, title, f"{message}: {str(ce)}")

    @staticmethod
    def copy_byte_provider_to_file(provider, dest_file, task_monitor):
        try:
            with provider.open('r') as is, open(dest_file, 'wb') as fos:
                return stream_copy(is, fos, task_monitor)
        except Exception as e:
            Msg.show_error(originator, parent, "Problem copying file", str(e))

    @staticmethod
    def get_lines(byte_provider):
        try:
            with byte_provider.open('r') as is:
                return FileUtilities.get_lines(is)
        except Exception as e:
            Msg.show_error(originator, parent, "Problem reading lines from provider", str(e))

    @staticmethod
    def get_md5(provider, task_monitor):
        try:
            message_digest = hashlib.md5()
            buf = bytearray(16 * 1024)
            while True:
                bytesRead = is.readinto(buf)
                if bytesRead == 0:
                    break
                message_digest.update(buf[:bytesRead])
                task_monitor.increment_progress(bytesRead)
                task_monitor.check_canceled()
            return NumericUtilities.convert_bytes_to_string(message_digest.digest())
        except Exception as e:
            Msg.show_error(originator, parent, "Problem calculating MD5", str(e))

    @staticmethod
    def append_path(*paths):
        if not paths[0]:
            return None
        buffer = StringBuilder()
        for path in paths:
            if not path or len(buffer) > 0 and SEPARATOR_CHARS.find(buffer.charAt(len(buffer)-1)) != -1:
                continue
            elif buffer.length() == 0 and (path.startswith('/') or os.path.isabs(path)):
                buffer.append('/')
            else:
                buffer.append('/' + path)
        return str(buffer)

    @staticmethod
    def get_extension(path, ext_level):
        for i in range(len(path)-1, -1, -1):
            c = path[i]
            if SEPARATOR_CHARS.find(c) != -1 or c == '.' and --ext_level <= 0:
                return path[i+1:]
        return None

    @staticmethod
    def normalize_native_path(path):
        return os.path.join('/', FilenameUtils.separatorsToUnix(path))

    @staticmethod
    def format_fstimESTAMP(d):
        if d is None:
            return "NA"
        df = dt.strptime(f"{d.year}-{d.month:02}-{d.day} {d.hour}:{d.minute}:{d.second}+{d.tzinfo}", "%Y-%m-%d %H:%M:%S%Z")
        return str(df)

    @staticmethod
    def format_size(length):
        if length is None:
            return "NA"
        else:
            return f"{length} ({FileUtilities.format_length(length)})"

    @staticmethod
    def unchecked_close(c, msg=None):
        try:
            c.close()
        except Exception as e:
            Msg.warn(FSUtilities.__class__, Objects.requireNonNullElse(msg, "Problem closing object"), str(e))
