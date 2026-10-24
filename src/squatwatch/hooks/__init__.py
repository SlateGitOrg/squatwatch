"""Static review of package build and install hooks (setup.py, PEP 517 backends,
.pth files, npm lifecycle scripts)."""

from squatwatch.hooks.review import review_path, review_tree

__all__ = ["review_path", "review_tree"]
