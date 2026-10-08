"""Contexts for managing Ghidra programs in ghidra-rpc.

A context wraps the Ghidra project and provides methods for loading binaries,
looking up programs, and running operations in the correct thread context.
"""

from __future__ import annotations

import hashlib
import logging
import os
import queue
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ghidra_rpc.server.decomp_cache import DecompileCache
from ghidra_rpc.session import Session

logger = logging.getLogger("ghidra-rpc.context")


@dataclass
class ProgramInfo:
    """Metadata and handles for a loaded binary."""

    name: str
    program: Any  # ghidra.program.model.listing.Program
    flat_api: Any  # ghidra.program.flatapi.FlatProgramAPI
    decompiler_pool: Any  # DecompilerPool
    metadata: dict
    analysis_complete: bool = False
    file_path: Path | None = None
    load_time: float | None = None
    decomp_cache: DecompileCache = field(default_factory=DecompileCache)


def _decompiler_pool_size() -> int:
    """Number of DecompInterface instances (native decompiler processes) per program.

    ``GHIDRA_RPC_DECOMPILERS`` overrides; the default is min(4, CPUs), at
    least 2.  Each instance is a separate decompiler process with its own
    memory footprint, so do not raise this blindly on small machines.
    """
    env = os.environ.get("GHIDRA_RPC_DECOMPILERS")
    if env:
        try:
            return max(1, min(32, int(env)))
        except ValueError:
            logger.warning("Ignoring invalid GHIDRA_RPC_DECOMPILERS=%r", env)
    return max(2, min(4, os.cpu_count() or 2))


def _new_decompiler_pool(program) -> "DecompilerPool":
    return DecompilerPool(lambda p=program: _setup_decompiler(p), size=_decompiler_pool_size())


def match_program(programs: dict, binary: str, *, not_found_hint: str) -> "ProgramInfo":
    """Resolve *binary* against a ``{key: ProgramInfo}`` mapping.

    Priority: exact key, then exact name (program name or key basename), then
    a unique substring of the key.  Exact names must win over substrings:
    with both ``ls`` and ``lsblk`` loaded, ``ls`` is not ambiguous.
    """
    if binary in programs:
        return programs[binary]

    exact = [(k, pi) for k, pi in programs.items()
             if binary == pi.name or binary == Path(k).name]
    if len(exact) == 1:
        return exact[0][1]
    if len(exact) > 1:
        raise ValueError(
            f"Ambiguous binary name '{binary}'. Matches: {[k for k, _ in exact]}"
        )

    partial = [(k, pi) for k, pi in programs.items() if binary in k]
    if len(partial) == 1:
        return partial[0][1]
    if len(partial) > 1:
        raise ValueError(
            f"Ambiguous binary name '{binary}'. Matches: {[k for k, _ in partial]}"
        )

    raise ValueError(
        f"Binary '{binary}' not found. Available: {list(programs.keys())}. "
        + not_found_hint
    )


class _SaveModeMixin:
    """Auto-save (default) or deferred save of programs after write commands.

    ``auto``: every write command saves the program to disk right away, so
    nothing is lost if the daemon dies.  ``deferred``: writes only mark the
    program dirty; it is flushed by an explicit ``save``, periodically by the
    server loop, and on shutdown.  Much faster for long annotation sessions on
    big programs, where each save rewrites database buffers.
    """

    save_mode: str = "auto"

    def _init_save_mode(self, session) -> None:
        mode = getattr(session, "save_mode", "auto") or "auto"
        if mode not in ("auto", "deferred"):
            raise ValueError(f"Invalid save mode: {mode!r} (use 'auto' or 'deferred')")
        self.save_mode = mode
        self._dirty: dict[str, ProgramInfo] = {}
        self._dirty_lock = threading.Lock()

    def save_program(self, pi: ProgramInfo, *, force: bool = False) -> None:
        if self.save_mode == "deferred" and not force:
            with self._dirty_lock:
                self._dirty[pi.name] = pi
            return
        self._save_now(pi)
        with self._dirty_lock:
            self._dirty.pop(pi.name, None)

    def dirty_programs(self) -> list[str]:
        with self._dirty_lock:
            return sorted(self._dirty)

    def flush_dirty(self) -> list[str]:
        with self._dirty_lock:
            pending = list(self._dirty.values())
            self._dirty.clear()
        saved = []
        for pi in pending:
            try:
                self._save_now(pi)
                saved.append(pi.name)
            except Exception:
                logger.warning("Deferred save of %s failed", pi.name, exc_info=True)
                with self._dirty_lock:
                    self._dirty.setdefault(pi.name, pi)
        return saved


class DecompilerPool:
    """Thread-safe pool of DecompInterface instances for concurrent decompilation."""

    def __init__(self, factory, *, size: int = 2):
        self._factory = factory
        self._size = max(1, size)
        self._queue: queue.LifoQueue = queue.LifoQueue(maxsize=self._size)
        self._created: list = []
        self._lock = threading.Lock()

    def _create(self):
        decompiler = self._factory()
        with self._lock:
            self._created.append(decompiler)
        return decompiler

    @property
    def size(self) -> int:
        return self._size

    @contextmanager
    def acquire(self):
        # Follow the pyghidra-mcp pattern: check capacity under lock,
        # but create outside the lock to avoid deadlock
        try:
            decompiler = self._queue.get_nowait()
        except queue.Empty:
            with self._lock:
                if len(self._created) < self._size:
                    need_create = True
                else:
                    need_create = False
            if need_create:
                decompiler = self._create()
            else:
                decompiler = self._queue.get()  # block until one is returned
        try:
            yield decompiler
        finally:
            self._queue.put(decompiler)

    def invalidate_all(self):
        with self._lock:
            for d in self._created:
                for method_name in ("flushCache", "resetDecompiler"):
                    m = getattr(d, method_name, None)
                    if m:
                        m()
                        break

    def dispose(self):
        with self._lock:
            decompilers = list(self._created)
            self._created.clear()
        while True:
            try:
                self._queue.get_nowait()
            except queue.Empty:
                break
        for d in decompilers:
            for method_name in ("dispose", "closeProgram"):
                m = getattr(d, method_name, None)
                if m:
                    m()
                    break


def _run_analysis(flat_api, program, *, timeout: int | None = None) -> bool:
    """Run analyzeAll(), optionally with a best-effort wall-clock timeout.

    Returns True if analysis completed normally, False if it was interrupted by
    the timeout.  The binary is still usable after a timeout — Ghidra will have
    completed whatever analysers finished within the time budget.
    """
    import threading

    if timeout is None:
        flat_api.analyzeAll(program)
        return True

    finished_event = threading.Event()
    exc_box: list[BaseException | None] = [None]

    def _worker():
        try:
            flat_api.analyzeAll(program)
        except BaseException as e:  # noqa: BLE001
            exc_box[0] = e
        finally:
            finished_event.set()

    t = threading.Thread(target=_worker, daemon=True, name="ghidra-analysis")
    t.start()
    completed = finished_event.wait(timeout=timeout)

    if not completed:
        # Best-effort cancellation via AutoAnalysisManager
        try:
            from ghidra.app.plugin.core.analysis import AutoAnalysisManager  # type: ignore
            mgr = AutoAnalysisManager.getAnalysisManager(program)
            for method in ("cancelCurrentAnalysis", "cancelQueuedTasks"):
                fn = getattr(mgr, method, None)
                if fn:
                    fn()
                    break
        except Exception:  # noqa: BLE001
            pass
        logger.warning(
            "Analysis timed out after %d s; proceeding with partial results.", timeout
        )
        return False

    if exc_box[0] is not None:
        raise exc_box[0]
    return True


def _setup_decompiler(program):
    """Create a configured DecompInterface for the given program."""
    from ghidra.app.decompiler import DecompileOptions, DecompInterface

    options = DecompileOptions()
    options.grabFromProgram(program)
    options.setMaxPayloadMBytes(100)

    decompiler = DecompInterface()
    decompiler.setOptions(options)
    decompiler.openProgram(program)
    return decompiler


def _gen_unique_bin_name(binary_path: Path) -> str:
    """Generate a unique program name from a binary path (name + sha1 prefix)."""
    sha1 = hashlib.sha1()
    with binary_path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha1.update(chunk)
    return f"{binary_path.name}-{sha1.hexdigest()[:6]}"


class HeadlessContext(_SaveModeMixin):
    """Context for headless (no GUI) Ghidra operation."""

    def __init__(self, session: Session):
        from ghidra.base.project import GhidraProject
        from ghidra.framework.model import ProjectLocator

        self.session = session
        self._init_save_mode(session)
        self.programs: dict[str, ProgramInfo] = {}
        self._programs_lock = threading.RLock()
        self._consumer = "ghidra-rpc"  # our own Program consumer token

        gpr = session.project_gpr
        project_dir = gpr.parent
        project_name = gpr.stem
        project_dir.mkdir(parents=True, exist_ok=True)

        locator = ProjectLocator(str(project_dir.resolve()), project_name)
        if locator.exists():
            self.project = GhidraProject.openProject(
                str(project_dir.resolve()), project_name, True
            )
        else:
            self.project = GhidraProject.createProject(
                str(project_dir.resolve()), project_name, False
            )

        logger.info(f"Opened headless project: {project_name}")

    def _take_ownership(self, program) -> None:
        """Release GhidraProject's permanently-open outer transaction on *program*.

        GhidraProject keeps every opened/imported program under one long-lived
        transaction until GhidraProject.save() settles it, so our own
        ghidra_transaction() calls nest inside it -- an aborted nested
        transaction then rolls back the whole intertwined group on the next
        flush (confirmed as intended Ghidra behavior, not a bug; see
        https://github.com/NationalSecurityAgency/ghidra/issues/9347).
        Becoming our own consumer and releasing the project's makes our
        transactions top-level instead.

        Must be called AFTER initial auto-analysis and its save() -- releasing
        ownership earlier silently breaks analyzeAll() (no functions get
        created despite it reporting success).
        """
        program.addConsumer(self._consumer)
        self.project.close(program)

    def load_binary(self, binary_path: str, *,
                    analyze: bool = True,
                    analysis_timeout: int | None = None) -> str:
        """Import a binary into the project, optionally run analysis, return program key.

        Parameters
        ----------
        analyze:
            When False the binary is imported but auto-analysis is skipped.
            Useful for large binaries when only the raw listing is needed.
        analysis_timeout:
            Wall-clock seconds budget for auto-analysis (best-effort).  When the
            timeout expires Ghidra's analysis manager is asked to cancel, but the
            binary is still saved with whatever analysis completed in time.
        """
        from ghidra.program.flatapi import FlatProgramAPI
        from ghidra.program.util import GhidraProgramUtilities

        path = Path(binary_path).resolve()
        if not path.exists():
            raise FileNotFoundError(f"Binary not found: {path}")

        program_name = _gen_unique_bin_name(path)

        # Check if already loaded in daemon memory
        with self._programs_lock:
            for key, pi in self.programs.items():
                if pi.name == program_name:
                    return key

        # Check if the program already exists in the project (previously saved).
        # If so, open it directly instead of re-importing from disk, which
        # would overwrite any previously completed analysis.
        key = f"/{program_name}"
        try:
            existing_df = self.project.getProjectData().getRootFolder().getFile(program_name)
        except Exception:
            existing_df = None

        # Fallback: programs imported via Ghidra GUI or older ghidra-rpc versions
        # may be stored under the bare filename (no hash suffix).  Try that name
        # so callers can open them without reimporting.
        if existing_df is None and path.name != program_name:
            try:
                bare_df = self.project.getProjectData().getRootFolder().getFile(path.name)
            except Exception:
                bare_df = None
            if bare_df is not None:
                existing_df = bare_df
                program_name = path.name
                key = f"/{program_name}"
                logger.info("Found bare-name program in project: %s", program_name)

        if existing_df is not None:
            # Re-open from the saved project copy.
            program = self.project.openProgram("/", program_name, False)
            flat_api = FlatProgramAPI(program)
            # Determine whether this copy was previously fully analyzed.
            try:
                already_analyzed = bool(
                    GhidraProgramUtilities.isAnalyzed(program)
                    if hasattr(GhidraProgramUtilities, "isAnalyzed")
                    else program.getFunctionManager().getFunctionCount() > 0
                )
            except Exception:
                already_analyzed = False

            analysis_complete = already_analyzed
            # If the caller wants analysis and the saved copy has none, run it now.
            if analyze and not already_analyzed:
                analysis_complete = _run_analysis(flat_api, program, timeout=analysis_timeout)
                if analysis_complete:
                    if hasattr(GhidraProgramUtilities, "setAnalyzedFlag"):
                        GhidraProgramUtilities.setAnalyzedFlag(program, True)
                    elif hasattr(GhidraProgramUtilities, "markProgramAnalyzed"):
                        GhidraProgramUtilities.markProgramAnalyzed(program)
                self.project.save(program)

            self._take_ownership(program)

            pi = ProgramInfo(
                name=program_name,
                program=program,
                flat_api=flat_api,
                decompiler_pool=_new_decompiler_pool(program),
                metadata=dict(program.getMetadata()),
                analysis_complete=analysis_complete,
                file_path=path,
                load_time=time.time(),
            )
            with self._programs_lock:
                self.programs[key] = pi
            logger.info("Re-opened from project (analysis_complete=%s): %s -> %s",
                        analysis_complete, program_name, key)
            return key

        imported_program = self.project.importProgram(path)
        if imported_program is None:
            raise RuntimeError(f"Failed to import binary: {path}")

        imported_program.name = program_name

        # Save into the project with the unique name, then re-open
        self.project.saveAs(imported_program, "/", program_name, True)
        self.project.close(imported_program)
        program = self.project.openProgram("/", program_name, False)

        flat_api = FlatProgramAPI(program)

        analysis_complete = False
        if analyze:
            analysis_complete = _run_analysis(flat_api, program, timeout=analysis_timeout)
            # Only mark as fully analyzed when analysis actually finished.
            # If it timed out, leave the flag unset so Ghidra knows it's partial.
            if analysis_complete:
                if hasattr(GhidraProgramUtilities, "setAnalyzedFlag"):
                    GhidraProgramUtilities.setAnalyzedFlag(program, True)
                elif hasattr(GhidraProgramUtilities, "markProgramAnalyzed"):
                    GhidraProgramUtilities.markProgramAnalyzed(program)

        self.project.save(program)
        self._take_ownership(program)

        key = f"/{program_name}"
        pi = ProgramInfo(
            name=program_name,
            program=program,
            flat_api=flat_api,
            decompiler_pool=_new_decompiler_pool(program),
            metadata=dict(program.getMetadata()),
            analysis_complete=analysis_complete,
            file_path=path,
            load_time=time.time(),
        )

        with self._programs_lock:
            self.programs[key] = pi

        logger.info("Loaded%s: %s -> %s",
                    " (no analysis)" if not analyze else "", program_name, key)
        return key

    def _save_now(self, pi: ProgramInfo) -> None:
        """Save a program's changes to the project database on disk."""
        self.project.save(pi.program)
        logger.debug("Saved program %s to project", pi.name)

    def get_program(self, binary: str) -> ProgramInfo:
        """Resolve a program by name, key, or path. Raises ValueError if not found or ambiguous."""
        with self._programs_lock:
            return match_program(
                self.programs, binary,
                not_found_hint=(
                    "Use 'ghidra-rpc load <path>' to import a binary, or "
                    "'ghidra-rpc list-binaries' to see loaded programs."
                ),
            )

    def close(self):
        """Clean up all resources, saving all programs first."""
        with self._programs_lock:
            for pi in self.programs.values():
                try:
                    self.project.save(pi.program)
                    logger.info("Saved program %s on shutdown", pi.name)
                except Exception:
                    logger.warning(
                        "Failed to save program %s on shutdown",
                        pi.name, exc_info=True,
                    )
                pi.decompiler_pool.dispose()
                # project released its consumer in _take_ownership; we're the sole one left
                pi.program.release(self._consumer)
            self.programs.clear()
        self.project.close()


class GuiContext(_SaveModeMixin):
    """Context for GUI mode Ghidra operation.

    All Ghidra GUI/program-state API calls go through Swing.runNow() to
    ensure thread safety with the Swing event dispatch thread.
    """

    def __init__(self, session: Session, launcher):
        from ghidra.framework.main import AppInfo

        self.session = session
        self._init_save_mode(session)
        self.launcher = launcher
        self.programs: dict[str, ProgramInfo] = {}
        self._programs_lock = threading.RLock()
        # Read-only commands now run concurrently and each one calls
        # get_program() -> refresh_programs(), which may open domain objects;
        # serialise refreshes so two readers never open the same program twice.
        self._refresh_lock = threading.Lock()

        # Wait for GUI to be ready
        self.project = self._wait_for_project(session, timeout=240.0)
        self.refresh_programs()
        logger.info("GUI context ready")

    @staticmethod
    def _normalize_project_location(loc_str: str) -> str:
        """Strip the URL-style leading slash Ghidra puts before a Windows drive letter.

        ``ProjectLocator.getLocation()`` returns a URL-derived path string, which
        on Windows looks like ``/C:/test/`` rather than ``C:/test/`` (the same
        convention as ``file:///C:/test/``'s path component). ``pathlib`` does
        not know this convention: ``Path("/C:/test/").resolve()`` parses it as
        *drive-relative* (``WindowsPath('C:test')``, no root) rather than
        absolute, so it can never equal an expected absolute path — meaning the
        comparison in ``_project_matches`` was unconditionally False on Windows,
        for every project, every time. Verified empirically on a real Windows
        VM. No-op on POSIX, where locations never start with ``/<letter>:``.
        """
        if len(loc_str) >= 3 and loc_str[0] in "/\\" and loc_str[2] == ":" and loc_str[1].isalpha():
            return loc_str[1:]
        return loc_str

    @staticmethod
    def _project_matches(project, session: "Session") -> bool:
        """Return True if *project* is the Ghidra project described by session.project_gpr.

        Key implementation notes:
        - ``ProjectLocator.getProjectDir()`` returns the ``.rep`` data *subdirectory*
          (e.g. ``/path/projA/projA.rep``), NOT the parent folder — do not use it
          for path comparison.
        - ``ProjectLocator.getLocation()`` returns the raw location string stored in
          the locator, which ``GhidraURL.checkLocalAbsolutePath`` normalises with a
          trailing ``/`` (e.g. ``/path/projA/``).  Wrap in ``Path.resolve()`` to
          strip the trailing slash before comparing.  On Windows it also carries
          a leading slash before the drive letter (``/C:/test/``) that must be
          stripped first — see ``_normalize_project_location``.
        """
        try:
            locator = project.getProjectLocator()
            # getLocation() → e.g. "/tmp/ghidra-multi-test/projA/" (POSIX) or
            # "/C:/test/" (Windows).
            loc_str = GuiContext._normalize_project_location(str(locator.getLocation()))
            actual_dir = Path(loc_str).resolve()
            expected_dir = session.project_gpr.parent.resolve()
            actual_name = str(locator.getName())
            expected_name = session.project_gpr.stem
            return actual_dir == expected_dir and actual_name == expected_name
        except Exception:
            return False

    @staticmethod
    def _wait_for_project(session: Session, timeout: float = 240.0):
        """Wait for Ghidra GUI to open the requested project.

        GhidraRun is passed the project path as a command-line argument (see
        GuiRpcLauncher._launch), so Ghidra opens it directly on startup without
        auto-restoring a different last-used project.  This method simply polls
        AppInfo.getActiveProject() until the matching project appears.

        If it does not appear within *timeout* seconds (e.g. because the project
        is locked by another Ghidra instance and the user dismissed the dialog),
        a RuntimeError is raised with a human-readable message.
        """
        from ghidra.framework.main import AppInfo

        deadline = time.time() + timeout
        last_log = 0.0
        while time.time() < deadline:
            try:
                project = AppInfo.getActiveProject()
                if project is not None and GuiContext._project_matches(project, session):
                    return project
            except Exception:
                pass

            # Periodically remind the user what we're waiting for (every 15 s).
            now = time.time()
            if now - last_log >= 15:
                logger.info(
                    "Waiting for Ghidra to open project: %s", session.project_gpr
                )
                last_log = now

            time.sleep(0.5)

        raise RuntimeError(
            f"Timed out waiting for Ghidra to open project: {session.project_gpr}\n"
            "If the project is locked by another Ghidra instance, close that "
            "instance first, then restart the daemon."
        )

    def run_on_swing(self, fn, *args, **kwargs):
        """Execute fn on the Swing EDT and return the result."""
        import jpype
        from ghidra.util import Swing
        from java.lang import Runnable  # type: ignore

        result_box = [None]
        exc_box = [None]

        def runnable():
            try:
                result_box[0] = fn(*args, **kwargs)
            except BaseException as e:
                exc_box[0] = e

        Swing.runNow(jpype.JProxy(Runnable, dict={"run": runnable}))
        if exc_box[0] is not None:
            raise exc_box[0]
        return result_box[0]

    def refresh_programs(self) -> None:
        """Sync internal program list with Ghidra's open programs (serialised)."""
        with self._refresh_lock:
            self._refresh_programs_unlocked()

    def _refresh_programs_unlocked(self) -> None:
        """Sync internal program list with Ghidra's open programs.

        Scans two sources:
        1. Programs currently open in a running tool (e.g. CodeBrowser).
        2. Programs stored in the project folder but not yet open in any tool
           — opened directly via the domain-file API so no GUI tool is required.
        """
        from ghidra.app.services import ProgramManager
        from ghidra.framework.main import AppInfo
        from ghidra.util.task import TaskMonitor

        # Always use the freshest active project (self.project may be stale after
        # a Ghidra project switch that happened after daemon startup).
        project = AppInfo.getActiveProject() or self.project

        active: dict[str, Any] = {}

        # --- Source 1: programs open in running tools ---
        try:
            for tool in project.getToolServices().getRunningTools():
                pm = tool.getService(ProgramManager)
                if pm is None:
                    continue
                for program in pm.getAllOpenPrograms():
                    df = program.getDomainFile()
                    key = str(df.getPathname()) if df else program.getName()
                    active[key] = program
                    logger.debug("Source1: found program %s", key)
        except Exception:
            logger.warning("refresh_programs Source1 failed", exc_info=True)

        # --- Source 2: programs stored in the project folder ---
        # This covers programs loaded into the project (e.g. by the user or a
        # previous ghidra-rpc load) that aren't currently open in any tool.
        try:
            root = project.getProjectData().getRootFolder()
            for df in root.getFiles():
                key = str(df.getPathname())
                if key in active:
                    continue
                logger.debug("Source2: trying to open %s", key)
                try:
                    # Use a plain string as the consumer (valid Java Object via JPype)
                    domain_obj = df.getDomainObject(
                        "ghidra-rpc", False, False, TaskMonitor.DUMMY
                    )
                    # Check it's a Program by duck-typing (isinstance is unreliable
                    # across the Java/Python boundary with JPype)
                    if hasattr(domain_obj, "getFunctionManager"):
                        active[key] = domain_obj
                        logger.debug("Source2: opened %s", key)
                    else:
                        domain_obj.release("ghidra-rpc")
                except Exception:
                    logger.warning("Could not open project file %s", key, exc_info=True)
        except Exception:
            logger.warning("Could not enumerate project folder", exc_info=True)

        logger.debug("refresh_programs: found %d programs: %s", len(active), list(active))

        with self._programs_lock:
            # Remove stale entries
            stale = set(self.programs) - set(active)
            for key in stale:
                self.programs[key].decompiler_pool.dispose()
                del self.programs[key]

            # Add/update entries
            for key, program in active.items():
                if key not in self.programs:
                    self.programs[key] = self._init_program_info(program)

    def _init_program_info(self, program) -> ProgramInfo:
        from ghidra.program.flatapi import FlatProgramAPI

        metadata = dict(program.getMetadata())
        exe_loc = metadata.get("Executable Location")

        return ProgramInfo(
            name=program.getName(),
            program=program,
            flat_api=FlatProgramAPI(program),
            decompiler_pool=_new_decompiler_pool(program),
            metadata=metadata,
            analysis_complete=self._is_analysis_complete(program),
            file_path=Path(exe_loc) if exe_loc else None,
            load_time=time.time(),
        )

    @staticmethod
    def _is_analysis_complete(program) -> bool:
        from ghidra.app.plugin.core.analysis import AutoAnalysisManager
        from ghidra.program.util import GhidraProgramUtilities

        try:
            if not bool(GhidraProgramUtilities.isAnalyzed(program)):
                return False
            mgr = AutoAnalysisManager.getAnalysisManager(program)
            return not bool(mgr.isAnalyzing())
        except Exception:
            return False

    def load_binary(self, binary_path: str, *,
                    analyze: bool = True,
                    analysis_timeout: int | None = None) -> str:
        """Import a binary into the GUI project, open in CodeBrowser, run analysis.

        Parameters
        ----------
        analyze:
            When False the binary is imported but auto-analysis is skipped.
        analysis_timeout:
            Wall-clock seconds budget for auto-analysis (best-effort).
        """
        from ghidra.app.util.importer import ProgramLoader
        from ghidra.util.task import TaskMonitor
        from java.io import File  # type: ignore
        from java.util import List  # type: ignore

        path = Path(binary_path).resolve()
        if not path.exists():
            raise FileNotFoundError(f"Binary not found: {path}")

        program_name = _gen_unique_bin_name(path)
        expected_key = f"/{program_name}"

        # Check if already loaded
        with self._programs_lock:
            if expected_key in self.programs:
                return expected_key

        # Import
        load_results = (
            ProgramLoader.builder()
            .source(File(str(path)))
            .project(self.project)
            .projectFolderPath("/")
            .name(program_name)
            .monitor(TaskMonitor.DUMMY)
            .load()
        )
        try:
            domain_file = load_results.getPrimary().save(TaskMonitor.DUMMY)
        finally:
            load_results.close()

        # Open in GUI
        self.project.getToolServices().launchDefaultTool(List.of(domain_file))

        # Wait for it to appear
        deadline = time.time() + 30
        while time.time() < deadline:
            self.refresh_programs()
            with self._programs_lock:
                if expected_key in self.programs:
                    break
            time.sleep(0.5)
        else:
            raise RuntimeError(f"Timed out waiting for GUI to open {expected_key}")

        if analyze:
            with self._programs_lock:
                pi = self.programs.get(expected_key)
            if pi is not None:
                completed = _run_analysis(pi.flat_api, pi.program, timeout=analysis_timeout)
                with self._programs_lock:
                    self.programs[expected_key].analysis_complete = completed

        return expected_key

    def _save_now(self, pi: ProgramInfo) -> None:
        """Save a program's changes to its project domain file on disk.

        In GUI mode a Ghidra background task (e.g. the decompiler or analysis
        manager) may have an open transaction shortly after a write operation.
        We retry a few times with a short delay before giving up; all changes
        are still held in Ghidra's undo/redo stack even if the disk save is
        deferred.
        """
        def do_save():
            from ghidra.util.task import TaskMonitor
            df = pi.program.getDomainFile()
            if df is not None:
                df.save(TaskMonitor.DUMMY)

        last_exc = None
        for attempt in range(6):   # up to ~3 s of retries
            try:
                self.run_on_swing(do_save)
                logger.debug("Saved program %s to project", pi.name)
                return
            except Exception as exc:
                last_exc = exc
                if "active transaction" in str(exc).lower():
                    time.sleep(0.5)
                else:
                    raise  # non-transaction errors propagate immediately

        # All retries exhausted — log a warning rather than crashing the handler.
        # The change is in Ghidra's undo stack; the user can save from the GUI.
        logger.warning(
            "Could not save %s after retries (active transaction held by "
            "a Ghidra background task): %s", pi.name, last_exc
        )

    def get_program(self, binary: str) -> ProgramInfo:
        """Resolve a program by name, key, or path."""
        self.refresh_programs()
        with self._programs_lock:
            return match_program(
                self.programs, binary,
                not_found_hint=(
                    "In GUI mode, open the binary in CodeBrowser first, or use "
                    "'ghidra-rpc load <path>' to import it."
                ),
            )

    def goto(self, binary: str, target: str, target_type: str) -> dict:
        """Navigate Ghidra GUI to a function or address."""
        from ghidra.app.services import GoToService, ProgramManager

        pi = self.get_program(binary)

        if target_type == "function":
            from ghidra_rpc.server.tools.decompiler import _find_function
            func = _find_function(pi, target)
            addr_obj = func.getEntryPoint()
        elif target_type == "address":
            addr_obj = _parse_address(pi.program, target)
        else:
            raise ValueError(f"Invalid target_type '{target_type}'. Use 'function' or 'address'.")

        tool = self._find_tool_for_program(pi.program)
        service = tool.getService(GoToService)
        if service is None:
            raise RuntimeError("No GoToService available in the active Ghidra tool.")

        def do_goto():
            return bool(service.goTo(addr_obj, pi.program))

        success = bool(self.run_on_swing(do_goto))
        return {"address": str(addr_obj), "success": success}

    def _find_tool_for_program(self, program):
        from ghidra.app.services import ProgramManager

        for tool in self.project.getToolServices().getRunningTools():
            pm = tool.getService(ProgramManager)
            if pm and program in list(pm.getAllOpenPrograms()):
                return tool
        raise RuntimeError("No Ghidra tool found for program.")

    def close(self):
        """Release context resources, saving all programs first."""
        with self._programs_lock:
            for pi in self.programs.values():
                try:
                    self._save_now(pi)
                    logger.info("Saved program %s on shutdown", pi.name)
                except Exception:
                    logger.warning(
                        "Failed to save program %s on shutdown",
                        pi.name, exc_info=True,
                    )
                pi.decompiler_pool.dispose()
            self.programs.clear()
        # Request GUI shutdown
        if hasattr(self.launcher, 'request_shutdown'):
            self.launcher.request_shutdown()


def _parse_address(program, address: str):
    """Parse a hex address string into a Ghidra Address object."""
    addr_str = address[2:] if address.lower().startswith("0x") else address
    addr = program.getAddressFactory().getAddress(addr_str)
    if addr is None:
        raise ValueError(f"Invalid address: {address}")
    return addr
