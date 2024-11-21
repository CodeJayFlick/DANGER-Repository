import os
import logging
from datetime import datetime

class UserAdmin:
    def __init__(self):
        pass

    @staticmethod
    def split_command(cmd):
        arg_list = []
        start_ix = 0
        end_ix = 0
        len_cmd = len(cmd)
        inside_quote = False
        while end_ix < len_cmd:
            c = cmd[end_ix]
            if not inside_quote and start_ix == end_ix:
                if c == ' ' or c == '"':
                    inside_quote = (c == '"')
                    start_ix = end_ix + 1
                    continue
            if c == (inside_quote * '"'):
                arg_list.append(cmd[start_ix:end_ix])
                start_ix = end_ix + 1
                inside_quote = False
            else:
                end_ix += 1
        if start_ix != end_ix:
            arg_list.append(cmd[start_ix:end_ix])
        args = [arg for arg in arg_list]
        return args

    @staticmethod
    def process_command(repository_mgr, cmd):
        user_mgr = repository_mgr.get_user_manager()
        args = UserAdmin.split_command(cmd)
        if args[0] == "-add":
            sid = args[1]
            pwd_hash = None
            if len(args) == 4 and args[2].lower() == "--p":
                pwd_hash = args[3].encode('utf-8')
            try:
                user_mgr.add_user(sid, pwd_hash)
                logging.info(f"User '{sid}' added")
            except DuplicateNameException as e:
                logging.error(f"Add User Failed: user '{sid}' already exists")

        elif args[0] == "-remove":
            sid = args[1]
            user_mgr.remove_user(sid)
            logging.info(f"User '{sid}' removed")

        elif args[0] == "-reset":
            sid = args[1]
            pwd_hash = None
            if len(args) == 4 and args[2].lower() == "--p":
                pwd_hash = args[3].encode('utf-8')
            if not user_mgr.reset_password(sid, pwd_hash):
                logging.info(f"Failed to reset password for user '{sid}'")
            elif pwd_hash is None:
                logging.info(f"User '{sid}' password reset to default")

        elif args[0] == "-dn":
            sid = args[1]
            x500_user = X500Principal(args[2])
            if user_mgr.is_valid_user(sid):
                user_mgr.set_distinguished_name(sid, x500_user)
                logging.info(f"User '{sid}' DN set ({x500_user.get_name()})")
            else:
                try:
                    user_mgr.add_user(sid, x500_user)
                    logging.info(f"User '{sid}' added with DN ({x500_user.get_name()}) and default password")
                except DuplicateNameException as e:
                    pass

        elif args[0] == "-admin":
            sid = args[1]
            rep_name = args[2]
            if not user_mgr.is_valid_user(sid):
                try:
                    user_mgr.add_user(sid)
                    logging.info(f"User '{sid}' added")
                except DuplicateNameException as e:
                    pass
            repository = repository_mgr.get_repository(rep_name)
            if repository is None:
                logging.error(f"Failed to add '{sid}' as admin, repository '{rep_name}' not found.")
            else:
                repository.add_admin(sid)

    @staticmethod
    def process_commands(repository_mgr):
        cmd_dir = os.path.join(repository_mgr.get_root_dir(), "admin")
        if not os.path.exists(cmd_dir):
            try:
                os.makedirs(cmd_dir)
            except Exception as e:
                logging.error(f"Failed to create command queue directory {cmd_dir}: possible permission problem")

        files = [f for f in os.listdir(cmd_dir) if f.endswith(".cmd")]
        if len(files) == 0:
            return

        log.info(f"Processing {len(files)} queued commands")
        for file in sorted([os.path.join(cmd_dir, f) for f in files], key=lambda x: datetime.fromtimestamp(os.stat(x).st_mtime)):
            with open(file, 'r') as cmd_file:
                lines = [line.strip() for line in cmd_file.readlines()]
                for command in lines:
                    if not command:
                        continue
                    UserAdmin.process_command(repository_mgr, command)
                os.remove(file)

    @staticmethod
    def write_commands(cmd_list, cmd_dir):
        with open(os.path.join(cmd_dir, "adm.tmp"), 'w') as f:
            for line in cmd_list:
                print(line, file=f)
        try:
            os.rename("adm.tmp", os.path.join(cmd_dir, "adm.cmd"))
        except Exception as e:
            logging.error(f"file error")
