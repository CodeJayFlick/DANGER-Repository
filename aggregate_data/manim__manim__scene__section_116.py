"""building blocks of segmented video API"""

import os
from enum import Enum
from typing import Any, Dict, List, Optional

from manim import get_video_metadata


class DefaultSectionType(str, Enum):
    """The type of a section can be used for third party applications.
    A presentation system could for example use the types to created loops.

    Examples
    --------
    This class can be reimplemented for more types::

        class PresentationSectionType(str, Enum):
            # start, end, wait for continuation by user
            NORMAL = "presentation.normal"
            # start, end, immediately continue to next section
            SKIP = "presentation.skip"
            # start, end, restart, immediately continue to next section when continued by user
            LOOP = "presentation.loop"
            # start, end, restart, finish animation first when user continues
            COMPLETE_LOOP = "presentation.complete_loop"
    """

    NORMAL = "default.normal"


class Section:
    """A :class:`.Scene` can be segmented into multiple Sections.
    Refer to :doc:`the documentation</tutorials/a_deeper_look>` for more info.
    It consists of multiple animations.

    Attributes
    ----------
    type
        Can be used by a third party applications to classify different types of sections.
    name
        Human readable, non-unique name for this section.
    partial_movie_files
        Animations belonging to this section.
    video
        Path to video file with animations belonging to section relative to sections directory.
        If ``None``, then the section will not be saved.

    See Also
    --------
    :class:`.DefaultSectionType`
    """

    def __init__(self, type: str, video: Optional[str], name: str):
        self.type = type
        # None when not to be saved -> still keeps section alive
        self.video: Optional[str] = video
        self.name = name
        self.partial_movie_files: List[Optional[str]] = []

    def is_empty(self) -> bool:
        """Check whether this section is empty.

        Note that animations represented by ``None`` are also counted.
        """
        return len(self.partial_movie_files) == 0

    def get_clean_partial_movie_files(self) -> List[str]:
        """Return all partial movie files that are not ``None``."""
        return [el for el in self.partial_movie_files if el is not None]

    def get_dict(self, sections_dir: str) -> Dict[str, Any]:
        """Get dictionary representation with metadata of output video.

        The output from this function is used from every section to build the sections index file.
        The output video must have been created in the ``sections_dir`` before executing this method.
        This is the main part of the Segmented Video API.
        """
        if self.video is None:
            raise ValueError(
                f"Section '{self.name}' cannot be exported as dict, it does not have a video path assigned to it"
            )

        video_metadata = get_video_metadata(os.path.join(sections_dir, self.video))
        return dict(
            {
                "name": self.name,
                "type": self.type,
                "video": self.video,
            },
            **video_metadata,
        )

    def __repr__(self):
        return f"<Section '{self.name}' stored in '{self.video}'>"
