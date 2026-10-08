"""Unit tests for GuiContext's project-matching logic (no Ghidra needed).

Regression coverage for a real bug found while verifying GUI mode on Windows:
ProjectLocator.getLocation() returns a URL-derived path with a leading slash
before a Windows drive letter (e.g. "/C:/test/"), which pathlib misparses as
drive-relative rather than absolute, so the comparison in _project_matches
was unconditionally False on Windows -- _wait_for_project timed out on every
GUI-mode start, regardless of whether Ghidra opened the correct project.
"""

from pathlib import Path
from types import SimpleNamespace

from ghidra_rpc.server.context import GuiContext


def _make_locator(location: str, name: str):
    return SimpleNamespace(getLocation=lambda: location, getName=lambda: name)


def _make_project(location: str, name: str):
    return SimpleNamespace(getProjectLocator=lambda: _make_locator(location, name))


class TestNormalizeProjectLocation:
    def test_strips_leading_slash_before_windows_drive_letter(self):
        assert GuiContext._normalize_project_location("/C:/test/") == "C:/test/"

    def test_lowercase_drive_letter(self):
        assert GuiContext._normalize_project_location("/c:/test/") == "c:/test/"

    def test_backslash_variant(self):
        assert GuiContext._normalize_project_location("\\C:\\test\\") == "C:\\test\\"

    def test_posix_path_untouched(self):
        loc = "/tmp/ghidra-multi-test/projA/"
        assert GuiContext._normalize_project_location(loc) == loc

    def test_already_bare_drive_path_untouched(self):
        assert GuiContext._normalize_project_location("C:/test/") == "C:/test/"


class TestProjectMatches:
    def test_matches_windows_style_location(self, monkeypatch):
        monkeypatch.setattr(Path, "resolve", lambda self: self, raising=False)
        session = SimpleNamespace(project_gpr=Path("C:/test/gui2.gpr"))
        project = _make_project("/C:/test/", "gui2")
        assert GuiContext._project_matches(project, session) is True

    def test_rejects_different_project_name(self, monkeypatch):
        monkeypatch.setattr(Path, "resolve", lambda self: self, raising=False)
        session = SimpleNamespace(project_gpr=Path("C:/test/gui2.gpr"))
        project = _make_project("/C:/test/", "other")
        assert GuiContext._project_matches(project, session) is False

    def test_swallows_locator_exceptions(self):
        session = SimpleNamespace(project_gpr=Path("C:/test/gui2.gpr"))
        broken_project = SimpleNamespace(
            getProjectLocator=lambda: (_ for _ in ()).throw(RuntimeError("boom"))
        )
        assert GuiContext._project_matches(broken_project, session) is False
