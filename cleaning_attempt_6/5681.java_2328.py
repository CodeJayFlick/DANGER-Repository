import threading
from collections import defaultdict

class FSCacheInfo:
    def __init__(self, fs):
        self.ref = fs.get_ref_manager().create()

class FileSystemInstanceManager:
    filesystem_purge_delay_ms = 60 * 1000  # 60 seconds

    def __init__(self, root_fs):
        self.root_fs = root_fs
        self.file_systems = defaultdict(dict)
        self.lock = threading.Lock()

    def clear(self):
        with self.lock:
            for fsrl_root in list(self.file_systems.keys()):
                fsci = self.file_systems[fsrl_root]
                try:
                    ref = fsci['ref']
                    filesystem = ref.get_filesystem()
                    if not ref.get_filesystem().get_ref_manager().can_close(ref):
                        print(f"Forcing filesystem closed: {filesystem}")
                    else:
                        filesystem.close()
                except Exception as e:
                    print(f"Error closing filesystem: {e}")

    def close_all_unused(self):
        with self.lock:
            unused_fses = [fsci for fsci in list(self.file_systems.values()) if not any(ref.get_filesystem().get_ref_manager().can_close(ref) for ref in fsci.values())]
            if unused_fses:
                print(f"Removing {len(unused_fses)} unused filesystems from cache")
            for fsi in unused_fses:
                self.release(fsi)

    def get_mounted_filesystems(self):
        with self.lock:
            return list(self.file_systems.keys())

    def add(self, fs):
        fsci = FSCacheInfo(fs)
        fs.get_ref_manager().add_listener(self)
        if not self.file_systems[fs.get_fsrl()].setdefault(fsci.ref, None):
            print("Added second instance of same filesystem!")
        return

    def get_ref(self, fsrl_root):
        with self.lock:
            fsci = self.file_systems.get(fsrl_root)
            if fsci is not None and 'ref' in fsci:
                return fsci['ref'].dup()
            elif root_fs.get_fsrl().is_equivalent(fsrl_root):
                return root_fs.get_ref_manager().create().dup()
        return None

    def is_filesystem_mounted_at(self, container_fsrl):
        with self.lock:
            for fsrl_root in list(self.file_systems.keys()):
                fsci = self.file_systems[fsrl_root]
                ref = fsci['ref']
                filesystem = ref.get_filesystem()
                if filesystem and filesystem.get_container().is_equivalent(container_fsrl):
                    return True
        return False

    def get_ref_mounted_at(self, container_fsrl):
        with self.lock:
            for fsrl_root in list(self.file_systems.keys()):
                fsci = self.file_systems[fsrl_root]
                ref = fsci['ref']
                filesystem = ref.get_filesystem()
                if filesystem and filesystem.get_container().is_equivalent(container_fsrl):
                    return ref.dup()
        return None

    def on_filesystem_close(self, fs):
        with self.lock:
            fsrl_root = fs.get_fsrl()
            del self.file_systems[fsrl_root]
            print(f"Filesystem {fsrl_root} was closed outside of cache")

    def on_filesystem_ref_change(self, fs, ref_manager):
        pass

    def cache_maint(self):
        with self.lock:
            unused_fses = [fsci for fsci in list(self.file_systems.values()) if not any(ref.get_filesystem().get_ref_manager().can_close(ref) for ref in fsci.values())]
            expired_fses = [fsi for fsi in unused_fses if (datetime.datetime.now() - datetime.timedelta(milliseconds=self.filesystem_purge_delay_ms)).timestamp() > time.time()]
            if expired_fses:
                print(f"Evicting {len(expired_fses)} filesystems from cache")
            for fsci in expired_fses:
                self.release(fsci)

    def get_expired(self, unused_fses):
        last_used_cutoff = datetime.datetime.now() - datetime.timedelta(milliseconds=self.filesystem_purge_delay_ms)
        results = []
        for fsi in unused_fses:
            ref_manager = fsi['ref'].get_filesystem().get_ref_manager()
            if (datetime.datetime.fromtimestamp(ref_manager.get_last_used_timestamp()) < last_used_cutoff):
                results.append(fsi)
        return results

    def get_unused_fses(self):
        results = []
        for fsrl_root in list(self.file_systems.keys()):
            fsci = self.file_systems[fsrl_root]
            ref_manager = fsci['ref'].get_filesystem().get_ref_manager()
            if ref_manager.can_close(fsci['ref']):
                results.append(fsci)
        return results

    def release(self, fsci):
        try:
            filesystem = fsci['ref'].get_filesystem()
            fsrl_root = filesystem.get_fsrl()

            self.file_systems[fsrl_root].pop('ref')
            ref_manager = fsci['ref'].get_filesystem().get_ref_manager()
            if not any(ref.get_filesystem().get_ref_manager().can_close(ref) for ref in fsci.values()):
                filesystem.close()
        except Exception as e:
            print(f"Error closing filesystem: {e}")

    def release_immediate(self, ref):
        try:
            fsi = self.file_systems[ref.get_filesystem().get_fsrl()]
            if 'ref' not in fsi:
                return
            ref.close()
            if not any(ref.get_filesystem().get_ref_manager().can_close(ref) for ref in fsi.values()):
                filesystem = fsi['ref'].get_filesystem()
                fsrl_root = filesystem.get_fsrl()

                self.file_systems[fsrl_root].pop('ref')
                filesystem.close()
        except Exception as e:
            print(f"Error closing filesystem: {e}")
