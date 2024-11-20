class GhidraLaunchable:
    def launch(self, layout: 'GhidraApplicationLayout', args: list) -> None:
        """Launches the launchable.

        Args:
            layout (GhidraApplicationLayout): The application layout to use for the launch.
            args (list[str]): The arguments passed through by GhidraLauncher.

        Raises:
            Exception: If there was a problem with the launch.
        """
        pass
