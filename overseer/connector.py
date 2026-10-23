"""
GDB Connector: Manages launching GDB, attaching to running processes,
and connecting to remote gdbserver instances with Overseer configured.
"""

import json
import os
import shutil
import subprocess
import sys
from typing import Any, Dict, List, Optional


class GDBConnector:
    """Controls GDB invocation and configuration."""

    def __init__(self, gdb_path: Optional[str] = None):
        self.gdb_path = gdb_path or shutil.which("gdb")
        if not self.gdb_path:
            raise FileNotFoundError("GDB binary not found in PATH.")

    def _get_tracker_script_path(self) -> str:
        """Get the absolute path to overseer/tracker.py."""
        cur_dir = os.path.dirname(os.path.abspath(__file__))
        return os.path.join(cur_dir, "tracker.py")

    def _build_env(self, config: Dict[str, Any]) -> Dict[str, str]:
        """Prepare environment variables for GDB subprocess."""
        env = dict(os.environ)
        env["OVERSEER_CONFIG"] = json.dumps(config)

        # Clear environment variables that corrupt GDB's embedded Python interpreter
        # (e.g. when running inside conda, virtualenv, or CI python toolcache)
        for var in (
            "PYTHONHOME",
            "PYTHONSTARTUP",
            "PYTHONEXECUTABLE",
            "PYTHONUSERBASE",
            "VIRTUAL_ENV",
            "CONDA_PREFIX",
            "CONDA_DEFAULT_ENV",
            "_PYTHON_SYSCONFIGDATA_NAME",
        ):
            env.pop(var, None)

        # Filter out foreign Python/Conda library paths from LD_LIBRARY_PATH so GDB
        # dynamically links against the system libpython it was built for
        if "LD_LIBRARY_PATH" in env:
            paths = env["LD_LIBRARY_PATH"].split(os.pathsep)
            clean_paths = [
                p for p in paths
                if not any(m in p for m in ("hostedtoolcache", "miniconda", "anaconda", "envs/", "venv", ".venv"))
            ]
            if clean_paths:
                env["LD_LIBRARY_PATH"] = os.pathsep.join(clean_paths)
            else:
                env.pop("LD_LIBRARY_PATH", None)

        # Ensure overseer parent dir is in PYTHONPATH so GDB's python can import overseer
        # without inheriting foreign stdlib or site-packages from caller
        overseer_pkg_parent = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        env["PYTHONPATH"] = overseer_pkg_parent

        return env

    def run_target(
        self,
        binary_path: str,
        args: Optional[List[str]] = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> int:
        """
        Run a target executable under GDB with Overseer syscall tracking.
        """
        if not os.path.exists(binary_path):
            raise FileNotFoundError(f"Binary not found: {binary_path}")

        full_config = dict(config or {})
        full_config["target"] = os.path.abspath(binary_path)
        full_config["args"] = args or []

        master_fd, slave_fd = None, None
        if full_config.get("pty", False):
            import pty
            master_fd, slave_fd = pty.openpty()
            full_config["inferior_tty"] = os.ttyname(slave_fd)

        tracker_script = self._get_tracker_script_path()
        env = self._build_env(full_config)

        cmd = [
            self.gdb_path,
            "-q",
            "-nx",
            "-batch",
            "-x",
            tracker_script,
            os.path.abspath(binary_path),
        ]

        try:
            proc = subprocess.Popen(
                cmd,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=sys.stdout,
                stderr=sys.stderr,
            )
            return proc.wait()
        finally:
            if slave_fd is not None:
                try:
                    os.close(slave_fd)
                except OSError:
                    pass
            if master_fd is not None:
                try:
                    os.close(master_fd)
                except OSError:
                    pass

    def attach_pid(
        self,
        pid: int,
        config: Optional[Dict[str, Any]] = None,
    ) -> int:
        """
        Attach GDB to an existing process PID with Overseer tracking.
        """
        full_config = dict(config or {})
        full_config["target"] = f"PID:{pid}"
        full_config["from_start"] = True  # Already running

        tracker_script = self._get_tracker_script_path()
        env = self._build_env(full_config)

        cmd = [
            self.gdb_path,
            "-q",
            "-nx",
            "-batch",
            "-p",
            str(pid),
            "-x",
            tracker_script,
        ]

        proc = subprocess.Popen(
            cmd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=sys.stdout,
            stderr=sys.stderr,
        )

        return proc.wait()

    def connect_remote(
        self,
        host_port: str,
        binary_path: Optional[str] = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> int:
        """
        Connect GDB to a remote gdbserver instance.
        """
        full_config = dict(config or {})
        full_config["target"] = f"remote:{host_port}"
        full_config["from_start"] = True

        tracker_script = self._get_tracker_script_path()
        env = self._build_env(full_config)

        cmd = [
            self.gdb_path,
            "-q",
            "-nx",
            "-batch",
            "-ex",
            f"target remote {host_port}",
            "-x",
            tracker_script,
        ]
        if binary_path:
            cmd.append(os.path.abspath(binary_path))

        proc = subprocess.Popen(
            cmd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=sys.stdout,
            stderr=sys.stderr,
        )

        return proc.wait()
