import argparse
from typing import List


class LogView:
    def __init__(self):
        self.detail = False
        self.path = None

    @property
    def detail(self):
        return self._detail

    @detail.setter
    def detail(self, value: bool):
        self._detail = value

    @property
    def path(self):
        return self._path

    @path.setter
    def path(self, value: str):
        self._path = value


def main():
    parser = argparse.ArgumentParser(description="Print raft logs from a log file")
    parser.add_argument("-d", "--detail", help="Show detail information of logs", action='store_true')
    parser.add_argument("-p", "--path", required=True, help="Specify a path for accurate hosts information")

    args = parser.parse_args()
    view = LogView()

    if args.detail:
        view.detail = True

    view.path = args.path

    log_deque_serializer = SyncLogDequeSerializer(view.path)
    logs = log_deque_serializer.get_all_entries_after_applied_index()
    state = log_deque_serializer.get_hard_state()
    manager_meta = log_deque_serializer.get_meta()

    print("-------------------LOG META-------------------------")
    print(manager_meta.__str__())
    print("-------------------LOG DATA-------------------------")
    print("-------------------NODE STATE-------------------------")
    print(state.__str__())
    print("-------------------NODE STATE-------------------------")

    data_file_list = log_deque_serializer.get_log_data_file_list()
    index_file_list = log_deque_serializer.get_log_index_file_list()

    for i in range(len(data_file_list)):
        print("name=" + str(data_file_list[i].getName()) + ",length=" + str(data_file_list[i].getLength()))
        print("name=" + str(index_file_list[i].getName()) + ",length=" + str(index_file_list[i].getLength()))

    count = 0

    for log in logs:
        print("Log NO " + str(count) + ": ")
        count += 1
        if view.detail:
            print(log.__str__())
        else:
            print(str(type(log)))

if __name__ == "__main__":
    main()
