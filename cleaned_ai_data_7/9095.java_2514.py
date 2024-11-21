import threading

class CreateNewSessionTask:
    def __init__(self, controller, state):
        self.controller = controller
        self.state = state

    def run(self):
        session = None
        name = None
        try:
            source_program = self.state[VTWizardStateKey.SOURCE_PROGRAM]
            destination_program = self.state[VTWizardStateKey.DESTINATION_PROGRAM]

            session = VTSessionDB.create_VT_session("New Session", source_program, destination_program)

            if isinstance(session, DomainObjectAdapterDB):
                dobj = session
            else:
                dobj = None

            source_program.release(self.controller.get_tool())
            destination_program.release(self.controller.get_tool())

            if dobj is not None:
                name = self.state[VTWizardStateKey.SESSION_NAME]
                folder = self.state[VTWizardStateKey.NEW_SESSION_FOLDER]

                try:
                    folder.create_file(name, dobj)
                except InvalidNameException as e:
                    print(f"Invalid Domain Object Name: {e}")

            final_session = session
            threading.Thread(target=lambda: self.controller.open_version_tracking_session(final_session)).start()
        except CancelledException:
            # the user cancelled; just cleanup
            if session is not None:
                release_domain_object(session)
        except IOException as e:
            if session is not None:
                release_domain_object(session)
            print(f"Failed to Create Session: {e}")

    def release_domain_object(self, session):
        if session is None:
            return

        ((VTSessionDB)session).release(self)

# Define the VTWizardStateKey
class VTWizardStateKey:
    SOURCE_PROGRAM = "source_program"
    DESTINATION_PROGRAM = "destination_program"
    SESSION_NAME = "session_name"
    NEW_SESSION_FOLDER = "new_session_folder"

