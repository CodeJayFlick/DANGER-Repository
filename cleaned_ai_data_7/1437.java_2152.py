class PtySession:
    def wait_exited(self):
        # Implement this method as needed.
        pass  # Return an integer status code if applicable.

    def destroy_forcibly(self):
        # Implement this method to terminate the session (leader and descendants).
        pass  # Release local resources used in maintaining and controlling the remote session, or release remote resources consumed by this session.
