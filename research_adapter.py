"""Opt-in, bounded bridge to the isolated ZERO GENESIS v1.6 simulator."""
from __future__ import annotations

import json
import math
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import ctypes
from ctypes import wintypes
from pathlib import Path

from resources import memory_status

# Research is disabled in the staging deployment. This non-existent default
# prevents a developer machine path from entering the published bundle.
DEFAULT_RESEARCH_ROOT = Path("/opt/marina/disabled-research")
MAX_SECONDS = 25
MAX_PROCESS_MEMORY = 384 * 1024 * 1024
MIN_FREE_MEMORY = 500 * 1024 * 1024
MAX_STDOUT = 32_000
MAX_BENCHMARK_BYTES = 5 * 1024 * 1024
MAX_REPORT_BYTES = 128 * 1024
MAX_SOURCE_FILES = 10000
MAX_SOURCE_BYTES = 64 * 1024 * 1024


def process_memory_limits_supported() -> bool:
    return os.name == "nt"

# This fixed script receives only an output directory. No chat text, user code, or state path enters it.
RUN_SCRIPT = r'''import json, sys
from pathlib import Path
import zero_genesis.v160_environment_inference as experiment
experiment.BOOTSTRAPS = 100  # Smoke mode only; decision metrics do not use the bootstrap interval.
out = Path(sys.argv[1])
r = experiment.run_v160(out, map_seeds=(86000,), eval_seeds=(96000,), budget=20)
summary = r["summary"]
print(json.dumps({
 "protocol": r["protocol"],
 "integrity": r["integrity"],
 "decision_metrics": {k: {"heldout_accuracy": v["latent_ig"]["heldout_accuracy"],
  "heldout_brier": v["latent_ig"]["heldout_brier"],
  "high_conf_negative_transfer_count": v["latent_ig"]["high_conf_negative_transfer_count"],
  "calibration_recovery_rate": v["latent_ig"]["calibration_recovery_rate"],
  "mean_information_gain": v["latent_ig"]["mean_information_gain"]}
  for k,v in summary["decisions"].items()},
 "bootstrap_replicates": experiment.BOOTSTRAPS,
 "map_seeds": r["map_seeds"], "evaluation_seeds": r["evaluation_seeds"]
}, separators=(",", ":")))
'''


class ResearchAdapterError(RuntimeError):
    pass


class ZeroGenesisResearchAdapter:
    def __init__(self, root: Path | None = None):
        self.root = Path(root or os.getenv("ZERO_GENESIS_RESEARCH_ROOT", str(DEFAULT_RESEARCH_ROOT))).resolve()

    def status(self) -> dict:
        valid = (self.root / "zero_genesis" / "v160_environment_inference.py").is_file()
        enabled = os.getenv("GENESIS_RESEARCH_ENABLED", "0").strip().lower() in {"1", "true", "yes"}
        archive_dir = (self.root / "results" / "v1_6").resolve()
        archive_available = (self.root in archive_dir.parents and
            (archive_dir / "benchmark.json").is_file() and (archive_dir / "research_report.md").is_file())
        return {"enabled": enabled, "available": valid, "archive_available": archive_available,
            "read_only": True,
            "protocol": "v1.6 isolated synthetic object/tool experiment" if valid else None,
            "engine_version": "ZERO GENESIS v1.6" if archive_available else None,
            "experiment_status": "archived_confirmatory_results" if archive_available else "unavailable"}

    def dashboard(self) -> dict:
        state = self.status()
        if not state["enabled"]:
            raise ResearchAdapterError("Research dashboard is disabled. Enable GENESIS_RESEARCH_ENABLED locally.")
        results_dir = (self.root / "results" / "v1_6").resolve()
        benchmark_path = results_dir / "benchmark.json"
        report_path = results_dir / "research_report.md"
        if self.root not in results_dir.parents or not state["archive_available"]:
            raise ResearchAdapterError("The archived ZERO GENESIS v1.6 benchmark/report is unavailable.")
        try:
            for path in (benchmark_path, report_path):
                resolved = path.resolve(strict=True)
                if self.root not in resolved.parents or not resolved.is_file():
                    raise ResearchAdapterError("Research artifacts must remain inside the configured source root.")
            if benchmark_path.stat().st_size > MAX_BENCHMARK_BYTES or report_path.stat().st_size > MAX_REPORT_BYTES:
                raise ResearchAdapterError("The archived research results exceed the read limits.")
            payload = json.loads(benchmark_path.read_text(encoding="utf-8"))
            report = report_path.read_text(encoding="utf-8")
        except ResearchAdapterError:
            raise
        except (OSError, ValueError, TypeError) as exc:
            raise ResearchAdapterError("Could not read the archived research results.") from exc
        if not str(payload.get("protocol", "")).startswith("v1.6"):
            raise ResearchAdapterError("The configured benchmark is not a v1.6 research result.")
        integrity = payload.get("integrity", {})
        required = ("disjoint_seed_ranges", "matched_arms", "source_training_is_direct",
            "agent_inputs_exclude_rule_maps", "no_live_state_path_used")
        if not all(integrity.get(key) is True for key in required):
            raise ResearchAdapterError("The archived benchmark failed its integrity checks.")
        summary = payload.get("summary", {})
        metrics = {}
        for regime, arms in summary.get("decisions", {}).items():
            metrics[regime] = {}
            for arm in ("learned", "frozen", "v140", "C_lcb", "latent_no_ig", "latent_ig", "local_ig"):
                values = arms.get(arm)
                if values:
                    metrics[regime][arm] = {key: values.get(key) for key in (
                        "first_accuracy", "heldout_accuracy", "heldout_brier",
                        "probe_failure_mean", "high_conf_negative_transfer_count",
                        "calibration_recovery_rate", "mean_information_gain")}
        marker = "## Interpretation and limitations"
        section = report.partition(marker)[2]
        limitations = section.split("\n## ", 1)[0].strip()[:6000] if section else "Archived report does not contain a limitations section."
        return {**state, "experiment_status": "completed_archived_benchmark",
            "protocol": payload.get("protocol"),
            "latest_benchmark": {"file": "results/v1_6/benchmark.json",
                "modified_at_epoch": benchmark_path.stat().st_mtime,
                "source_map_count": len(payload.get("map_seeds", [])),
                "evaluation_map_count": len(payload.get("evaluation_seeds", [])), "integrity": integrity},
            "decision_metrics": metrics, "full_world_metrics": summary.get("worlds", {}),
            "known_limitations": limitations,
            "chat_isolation": "Research results are read-only and never enter chat prompts or responses."}

    def run_sample(self) -> dict:
        status = self.status()
        if not status["enabled"]:
            raise ResearchAdapterError("Research processing is disabled. Set GENESIS_RESEARCH_ENABLED=1 to opt in.")
        if not status["available"]:
            raise ResearchAdapterError("The configured ZERO GENESIS v1.6 research source is unavailable.")
        if not process_memory_limits_supported():
            raise ResearchAdapterError("Research execution is unavailable on this platform because a process memory limit cannot be enforced safely.")
        source_bytes = self._bounded_source_size(self.root / "zero_genesis")
        if source_bytes is None:
            raise ResearchAdapterError("Research source exceeds the configured file-count or copy-size limit.")
        available = memory_status().get("available_bytes")
        if available is not None and available < MIN_FREE_MEMORY:
            raise ResearchAdapterError("Research run skipped because available system memory is below 500 MiB.")
        env = {key: os.environ[key] for key in ("PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP") if os.getenv(key)}
        env.update({"PYTHONDONTWRITEBYTECODE": "1", "PYTHONIOENCODING": "utf-8"})
        try:
            with tempfile.TemporaryDirectory(prefix="genesis-zero-research-") as temp:
                temporary_root = Path(temp)
                isolated_root = temporary_root / "source"
                shutil.copytree(self.root / "zero_genesis", isolated_root / "zero_genesis",
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
                output_dir = temporary_root / "output"
                command = [sys.executable, "-c", RUN_SCRIPT, str(output_dir)]
                proc = subprocess.Popen(command, cwd=isolated_root, env=env, stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, close_fds=True)
                job = self._apply_windows_memory_limit(proc)
                stdout_bytes = bytearray()
                output_exceeded = threading.Event()
                def drain_stdout():
                    assert proc.stdout is not None
                    while True:
                        chunk = proc.stdout.read(4096)
                        if not chunk:
                            return
                        if len(stdout_bytes) + len(chunk) > MAX_STDOUT:
                            output_exceeded.set()
                            try:
                                proc.kill()
                            except OSError:
                                pass
                            return
                        stdout_bytes.extend(chunk)
                reader = threading.Thread(target=drain_stdout, name="marina-research-stdout", daemon=True)
                reader.start()
                try:
                    proc.wait(timeout=MAX_SECONDS)
                except subprocess.TimeoutExpired as exc:
                    proc.kill()
                    proc.wait()
                    raise ResearchAdapterError("Research run stopped after the 25 second limit.") from exc
                finally:
                    reader.join(timeout=2)
                    if job:
                        ctypes.windll.kernel32.CloseHandle(job)
        except subprocess.TimeoutExpired as exc:
            raise ResearchAdapterError("Research run stopped after the 25 second limit.") from exc
        except OSError as exc:
            raise ResearchAdapterError(f"Could not start isolated research process: {exc}") from exc
        if output_exceeded.is_set() or reader.is_alive():
            raise ResearchAdapterError("Research result exceeded the output limit.")
        if proc.returncode:
            raise ResearchAdapterError("Research process failed.")
        try:
            result = json.loads(stdout_bytes.decode("utf-8"))
        except ValueError as exc:
            raise ResearchAdapterError("Research process returned an invalid result.") from exc
        self._validate_result(result)
        return {"status": "completed", "label": "Experimental simulator observations (separate from chat)",
                "result": result, "duration_limit_seconds": MAX_SECONDS,
                "memory_limit_bytes": MAX_PROCESS_MEMORY,
                "state_policy": "fresh seeded simulator state in a temporary directory; no research state/checkpoints read or written"}

    @staticmethod
    def _bounded_source_size(root: Path) -> int | None:
        total = files = 0
        if root.is_symlink():
            return None
        pending = [root]
        try:
            while pending:
                directory = pending.pop()
                for entry in directory.iterdir():
                    if entry.is_symlink():
                        return None
                    if entry.is_dir():
                        pending.append(entry)
                    elif entry.is_file():
                        files += 1
                        total += entry.stat().st_size
                        if files > MAX_SOURCE_FILES or total > MAX_SOURCE_BYTES:
                            return None
            return total
        except OSError as exc:
            raise ResearchAdapterError("Research source could not be safely inspected.") from exc

    @staticmethod
    def _validate_result(result: dict) -> None:
        regimes = {"same_map", "global_permutation", "sparse_change", "independent_map"}
        integrity_fields = {"disjoint_seed_ranges", "matched_arms", "source_training_is_direct", "agent_inputs_exclude_rule_maps", "no_live_state_path_used"}
        metric_fields = {"heldout_accuracy", "heldout_brier", "high_conf_negative_transfer_count", "calibration_recovery_rate", "mean_information_gain"}
        if not isinstance(result, dict) or result.get("protocol") != "v1.6 preregistered latent environment inference research":
            raise ResearchAdapterError("Research result failed protocol validation.")
        integrity = result.get("integrity")
        if not isinstance(integrity, dict) or set(integrity) != integrity_fields or not all(value is True for value in integrity.values()):
            raise ResearchAdapterError("Research result failed integrity validation.")
        metrics = result.get("decision_metrics")
        if not isinstance(metrics, dict) or set(metrics) != regimes:
            raise ResearchAdapterError("Research result has an invalid regime set.")
        for row in metrics.values():
            if not isinstance(row, dict) or set(row) != metric_fields:
                raise ResearchAdapterError("Research result has invalid metric fields.")
            if any(not isinstance(value, (int, float)) or not math.isfinite(value) for value in row.values()):
                raise ResearchAdapterError("Research result contains a non-finite or non-numeric metric.")
        if result.get("map_seeds") != [86000] or result.get("evaluation_seeds") != [96000]:
            raise ResearchAdapterError("Research result did not use the approved fixed seeds.")
        if result.get("bootstrap_replicates") != 100:
            raise ResearchAdapterError("Research result used an unexpected smoke-mode bootstrap count.")

    @staticmethod
    def _apply_windows_memory_limit(process):
        if os.name != "nt":
            return None

        class BASIC_LIMITS(ctypes.Structure):
            _fields_ = [("PerProcessUserTimeLimit", ctypes.c_longlong), ("PerJobUserTimeLimit", ctypes.c_longlong),
                ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD), ("SchedulingClass", wintypes.DWORD)]
        class IO_COUNTERS(ctypes.Structure):
            _fields_ = [(name, ctypes.c_ulonglong) for name in ("ReadOperationCount", "WriteOperationCount", "OtherOperationCount", "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]
        class EXTENDED_LIMITS(ctypes.Structure):
            _fields_ = [("BasicLimitInformation", BASIC_LIMITS), ("IoInfo", IO_COUNTERS),
                ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]
        kernel = ctypes.windll.kernel32
        kernel.CreateJobObjectW.restype = wintypes.HANDLE
        kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        kernel.SetInformationJobObject.restype = wintypes.BOOL
        kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        kernel.AssignProcessToJobObject.restype = wintypes.BOOL
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.restype = wintypes.BOOL
        job = kernel.CreateJobObjectW(None, None)
        if not job:
            process.kill()
            raise ResearchAdapterError("Could not create the research memory-limits job.")
        limits = EXTENDED_LIMITS()
        # Process CPU time, single active process, per-process/job memory, and
        # kill-on-close bound the fixed research child on supported Windows hosts.
        limits.BasicLimitInformation.LimitFlags = 0x2 | 0x8 | 0x100 | 0x200 | 0x2000
        limits.BasicLimitInformation.PerProcessUserTimeLimit = MAX_SECONDS * 10_000_000
        limits.BasicLimitInformation.ActiveProcessLimit = 1
        limits.ProcessMemoryLimit = MAX_PROCESS_MEMORY
        limits.JobMemoryLimit = MAX_PROCESS_MEMORY
        if not kernel.SetInformationJobObject(job, 9, ctypes.byref(limits), ctypes.sizeof(limits)) or not kernel.AssignProcessToJobObject(job, wintypes.HANDLE(process._handle)):
            kernel.CloseHandle(job)
            process.kill()
            raise ResearchAdapterError("Could not enforce the 384 MiB research process memory limit.")
        return job
