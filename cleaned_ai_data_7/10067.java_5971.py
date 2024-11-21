import threading
import queue

class RepositoryChangeDispatcher:
    def __init__(self, rep_adapter):
        self.rep_adapter = rep_adapter
        self.change_listener = None
        self.thread = None

    def run(self):
        while self.thread and not self.thread.is_alive():
            events = self.rep_adapter.get_events()
            if events:
                for event in events:
                    self.process_event(event)

    def set_file_change_listener(self, change_listener):
        self.change_listener = change_listener

    def stop(self):
        if self.thread:
            self.thread.interrupt()

    def start(self):
        self.stop()
        self.thread = threading.Thread(target=self.run, name=f"RepChangeDispatcher-{self.rep_adapter.name}")
        self.thread.daemon = True
        self.thread.start()

    def process_event(self, event):
        if not self.change_listener:
            return

        for i in range(len(event)):
            e = events[i]
            match e.type:
                case RepositoryChangeEvent.REP_OPEN_HANDLE_COUNT:
                    self.rep_adapter.process_open_handle_count_update_event(e)
                case RepositoryChangeEvent.REP_FOLDER_CREATED:
                    self.change_listener.folder_created(e.parent_path, e.name)
                case RepositoryChangeEvent.REP_FOLDER_DELETED:
                    self.change_listener.folder_deleted(e.parent_path, e.name)
                case RepositoryChangeEvent.REP_FOLDER_MOVED:
                    self.change_listener.folder_moved(e.parent_path, e.name, e.new_parent_path)
                case RepositoryChangeEvent.REP_FOLDER_RENAMED:
                    self.change_listener.folder_renamed(e.parent_path, e.name, e.new_name)
                case RepositoryChangeEvent.REP_ITEM_CHANGED:
                    self.change_listener.item_changed(e.parent_path, e.name)
                case RepositoryChangeEvent.REP_ITEM_CREATED:
                    self.change_listener.item_created(e.parent_path, e.name)
                case RepositoryChangeEvent.REP_ITEM_DELETED:
                    self.change_listener.item_deleted(e.parent_path, e.name)
                case RepositoryChangeEvent.REP_ITEM_MOVED:
                    self.change_listener.item_moved(e.parent_path, e.name, e.new_parent_path, e.new_name)
                case RepositoryChangeEvent.REP_ITEM_RENAMED:
                    self.change_listener.item_renamed(e.parent_path, e.name, e.new_name)

class RepositoryAdapter:
    def get_events(self):
        # implement this method to return a list of events
        pass

class FileSystemListener:
    def folder_created(self, parent_path, name):
        raise NotImplementedError("folder_created not implemented")

    def folder_deleted(self, parent_path, name):
        raise NotImplementedError("folder_deleted not implemented")

    def folder_moved(self, parent_path, name, new_parent_path):
        raise NotImplementedError("folder_moved not implemented")

    def folder_renamed(self, parent_path, name, new_name):
        raise NotImplementedError("folder_renamed not implemented")

    def item_changed(self, parent_path, name):
        raise NotImplementedError("item_changed not implemented")

    def item_created(self, parent_path, name):
        raise NotImplementedError("item_created not implemented")

    def item_deleted(self, parent_path, name):
        raise NotImplementedError("item_deleted not implemented")

    def item_moved(self, parent_path, name, new_parent_path, new_name):
        raise NotImplementedError("item_moved not implemented")

    def item_renamed(self, parent_path, name, new_name):
        raise NotImplementedError("item_renamed not implemented")
