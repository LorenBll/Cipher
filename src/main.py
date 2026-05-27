"""Cipher local web service."""

from __future__ import annotations

import json
import logging
import os
import socket
import time
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock, Thread
from typing import Any
from uuid import uuid4

from cryptography.fernet import Fernet, InvalidToken
from flask import Flask, jsonify, request

logger = logging.getLogger(__name__)

CONFIG_PATH = Path(__file__).resolve().parent.parent / "resources" / "configuration.json"
SERVICE_BIND_ADDRESS = "127.0.0.1"
DEFAULT_SERVICE_PORT = 49160
SERVICE_PORT: int | None = None

try:
    TASK_RETENTION_MINUTES = int(os.getenv("TASK_RETENTION_MINUTES", "30"))
except (TypeError, ValueError):
    TASK_RETENTION_MINUTES = 30

try:
    TASK_CLEANUP_INTERVAL_SECONDS = int(
        os.getenv("TASK_CLEANUP_INTERVAL_SECONDS", "60")
    )
except (TypeError, ValueError):
    TASK_CLEANUP_INTERVAL_SECONDS = 60

app = Flask(__name__)

jobs_lock = Lock()
jobs: dict[str, dict[str, Any]] = {}

cleanup_lock = Lock()
cleanup_thread_started = False


def _utc_iso() -> str:
    """Return the current UTC time in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


def _load_configuration() -> dict[str, Any]:
    """Load configuration from resources/configuration.json."""
    if not CONFIG_PATH.exists():
        # Avoid exposing full filesystem paths in exception messages.
        logger.debug("Configuration file missing: %s", CONFIG_PATH)
        raise FileNotFoundError("Configuration file not found. Ensure configuration.json exists.")

    try:
        with open(CONFIG_PATH, "r", encoding="utf-8-sig") as config_file:
            config = json.load(config_file)
    except json.JSONDecodeError as exc:
        logger.debug("Invalid JSON in configuration file %s: %s", CONFIG_PATH, exc)
        raise ValueError("Configuration file contains invalid JSON") from exc
    except Exception as exc:
        logger.debug("Failed to read configuration file %s: %s", CONFIG_PATH, exc)
        raise RuntimeError("Failed to read configuration file") from exc

    return config


def _initialize_service_config() -> None:
    """Load and validate the service configuration."""
    global SERVICE_PORT

    config = _load_configuration()
    configured_port = config.get("port", DEFAULT_SERVICE_PORT)

    if isinstance(configured_port, str) and configured_port.isdigit():
        configured_port = int(configured_port)

    if not isinstance(configured_port, int):
        raise ValueError("port in configuration.json must be an integer")

    SERVICE_PORT = configured_port


def _collect_local_ip_addresses() -> list[str]:
    """Gather the IPv4 addresses resolved for the local machine."""
    addresses: set[str] = {"127.0.0.1"}
    hostnames = {socket.gethostname(), socket.getfqdn(), "localhost"}

    for hostname in hostnames:
        if not hostname:
            continue

        try:
            _, _, resolved_addresses = socket.gethostbyname_ex(hostname)
        except OSError:
            resolved_addresses = []

        for address in resolved_addresses:
            if _is_ipv4_address(address):
                addresses.add(address)

        try:
            for family, _, _, _, sockaddr in socket.getaddrinfo(hostname, None):
                if family == socket.AF_INET and sockaddr:
                    candidate = sockaddr[0]
                    if _is_ipv4_address(candidate):
                        addresses.add(candidate)
        except OSError:
            continue

    return sorted(addresses, key=_sort_ip_address)


def _is_ipv4_address(value: object) -> bool:
    """Check whether a value is a valid IPv4 address string."""
    if not isinstance(value, str):
        return False

    parts = value.strip().split(".")
    if len(parts) != 4:
        return False

    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False


def _sort_ip_address(value: str) -> tuple[int, int, int, int]:
    """Sort IP addresses numerically while keeping loopback near the front."""
    parts = value.split(".")
    if len(parts) != 4:
        return (255, 255, 255, 255)

    try:
        return tuple(int(part) for part in parts)  # type: ignore[return-value]
    except ValueError:
        return (255, 255, 255, 255)


def _get_primary_ip() -> str:
    """Return the first non-loopback IPv4 address, or loopback as a fallback."""
    for address in _collect_local_ip_addresses():
        if address != "127.0.0.1":
            return address
    return "127.0.0.1"


def _ensure_cleanup_thread_started() -> None:
    """Start cleanup thread exactly once."""
    global cleanup_thread_started
    with cleanup_lock:
        if cleanup_thread_started:
            return
        cleanup_thread = Thread(
            target=_cleanup_finished_jobs_forever,
            name="cipher-task-cleanup-worker",
            daemon=True,
        )
        cleanup_thread.start()
        cleanup_thread_started = True


def _cleanup_finished_jobs_forever() -> None:
    """Remove finished tasks after a retention period."""
    retention_seconds = max(60, TASK_RETENTION_MINUTES * 60)
    interval_seconds = max(10, TASK_CLEANUP_INTERVAL_SECONDS)

    while True:
        try:
            time.sleep(interval_seconds)
            now = time.time()
            removable_task_ids: list[str] = []

            with jobs_lock:
                for task_id, task in jobs.items():
                    if task.get("status") not in {"completed", "failed"}:
                        continue

                    finished_at = task.get("finished_at_unix")
                    if (
                        isinstance(finished_at, (int, float))
                        and (now - finished_at) >= retention_seconds
                    ):
                        removable_task_ids.append(task_id)

                for task_id in removable_task_ids:
                    jobs.pop(task_id, None)
        except Exception as exc:
            logger.error("Cleanup thread error: %s", exc)


def _error_response(message: str, status_code: int = 400) -> tuple[Any, int]:
    """Return a JSON error response."""
    return jsonify({"error": message}), status_code


def _require_string(payload: object, field_name: str) -> str:
    """Extract a non-empty string field from a JSON payload."""
    if not isinstance(payload, str) or not payload.strip():
        raise ValueError("Required string field is missing or empty")
    return payload.strip()


def _require_absolute_path(value: object, field_name: str) -> Path:
    """Validate that a payload field is an absolute filesystem path."""
    path_value = _require_string(value, field_name)
    # Use resolve(strict=False) to canonicalize the path without requiring
    # it to exist yet. This helps avoid path traversal tricks such as '..'.
    path = Path(path_value)
    resolved = path.resolve(strict=False)
    if not str(resolved).startswith(os.path.sep) and not resolved.drive:
        raise ValueError("Invalid absolute path")
    return resolved


def _normalize_file_paths(value: object, field_name: str) -> list[Path]:
    """Normalize a single file path or a list of file paths."""
    if isinstance(value, str):
        values: list[object] = [value]
    elif isinstance(value, list):
        values = list(value)
    else:
        raise ValueError("file_path must be a string or list of strings")

    if not values:
        raise ValueError("file_path must contain at least one file path")

    normalized_paths: list[Path] = []
    for index, item in enumerate(values, start=1):
        normalized_paths.append(
            _require_absolute_file_path(item, f"{field_name}[{index}]")
        )
    return normalized_paths


def _is_within_directory(child: Path, parent: Path) -> bool:
    """Return True if `child` is inside `parent` (or equal), after resolving."""
    try:
        child_resolved = child.resolve()
        parent_resolved = parent.resolve()
    except Exception:
        return False
    try:
        child_resolved.relative_to(parent_resolved)
        return True
    except Exception:
        return False


def _require_absolute_file_path(value: object, field_name: str) -> Path:
    """Validate that a path exists and points to a file."""
    path = _require_absolute_path(value, field_name)
    if not path.exists():
        raise ValueError("Specified path does not exist")
    if not path.is_file():
        raise ValueError("Specified path is not a file")
    # Return the resolved absolute path to avoid later surprises.
    return path.resolve()


def _resolve_unique_path(directory: Path, file_name: str) -> Path:
    """Return a unique path by appending a counter before the suffixes."""
    candidate = directory / file_name
    if not candidate.exists():
        return candidate

    suffix = "".join(Path(file_name).suffixes)
    stem = file_name[: -len(suffix)] if suffix else file_name
    counter = 1
    while True:
        if suffix:
            candidate = directory / f"{stem} ({counter}){suffix}"
        else:
            candidate = directory / f"{stem} ({counter})"
        if not candidate.exists():
            return candidate
        counter += 1


def _load_fernet(key_path: Path) -> Fernet:
    """Load a Fernet instance from a key file."""
    key_bytes = key_path.read_bytes().strip()
    if not key_bytes:
        logger.debug("Key file appears empty: %s", key_path)
        raise ValueError("Key file is empty")
    return Fernet(key_bytes)


def _encryption_output_path(source_path: Path) -> Path:
    """Build an output path for encrypted files."""
    return _resolve_unique_path(source_path.parent, f"{source_path.name}.fernet")


def _decryption_output_path(source_path: Path) -> Path:
    """Build an output path for decrypted files."""
    if source_path.name.endswith(".fernet"):
        return _resolve_unique_path(
            source_path.parent,
            source_path.name[: -len(".fernet")],
        )

    return _resolve_unique_path(
        source_path.parent,
        f"{source_path.name}.decrypted",
    )


def _create_key_file(directory_path: Path, file_name: str) -> Path:
    """Create a Fernet key file after validating the destination."""
    # Ensure file_name is a simple filename (no directories or traversal).
    safe_name = Path(file_name).name
    if safe_name != file_name or file_name in {".", ".."}:
        raise ValueError("file_name must be a simple file name without path components")

    if not directory_path.exists():
        raise ValueError("directory_path does not exist")
    if not directory_path.is_dir():
        raise ValueError("directory_path must point to a directory")

    key_path = directory_path / safe_name
    if key_path.exists():
        raise ValueError("A file with that name already exists in the destination directory")

    key_path.write_bytes(Fernet.generate_key())
    return key_path


def _create_task(operation: str, key_path: Path, file_paths: list[Path]) -> dict[str, Any]:
    """Register a new background task and return the task record."""
    task_id = str(uuid4())
    now = _utc_iso()

    with jobs_lock:
        jobs[task_id] = {
            "task_id": task_id,
            "operation": operation,
            "status": "queued",
            "created_at": now,
            "updated_at": now,
            # Store only basenames for any paths to avoid leaking local filesystem layout.
            "key_path": key_path.name,
            "file_paths": [path.name for path in file_paths],
        }

    return jobs[task_id]


def _finalize_task_success(task_id: str, result: dict[str, Any]) -> None:
    """Mark a task as completed."""
    with jobs_lock:
        jobs[task_id]["status"] = "completed"
        jobs[task_id]["result"] = result
        jobs[task_id]["updated_at"] = _utc_iso()
        jobs[task_id]["finished_at_unix"] = time.time()


def _finalize_task_failure(task_id: str, error_message: str) -> None:
    """Mark a task as failed."""
    # Store a short, non-sensitive error message for API consumers. Detailed
    # exception info is logged at debug level for operators.
    sanitized = "Task failed during processing"
    with jobs_lock:
        jobs[task_id]["status"] = "failed"
        jobs[task_id]["error"] = sanitized
        jobs[task_id]["updated_at"] = _utc_iso()
        jobs[task_id]["finished_at_unix"] = time.time()


def _cipher_worker(task_id: str, operation: str, key_path: Path, file_paths: list[Path]) -> None:
    """Process encryption or decryption work in the background."""
    with jobs_lock:
        jobs[task_id]["status"] = "in_progress"
        jobs[task_id]["updated_at"] = _utc_iso()

    try:
        fernet = _load_fernet(key_path)
        processed_files: list[dict[str, str]] = []

        for source_path in file_paths:
            if operation == "encrypt":
                output_path = _encryption_output_path(source_path)
                output_path.write_bytes(fernet.encrypt(source_path.read_bytes()))
            elif operation == "decrypt":
                output_path = _decryption_output_path(source_path)
                output_path.write_bytes(fernet.decrypt(source_path.read_bytes()))
            else:
                raise ValueError(f"Unsupported operation: {operation}")

            # Only keep file names in the recorded result to avoid leaking
            # absolute paths in the API.
            processed_files.append(
                {
                    "input_name": source_path.name,
                    "output_name": output_path.name,
                }
            )

        _finalize_task_success(
            task_id,
            {
                "operation": operation,
                "file_count": len(processed_files),
                "files": processed_files,
            },
        )
    except InvalidToken as exc:
        logger.debug("InvalidToken while processing task %s: %s", task_id, exc)
        _finalize_task_failure(task_id, "Invalid Fernet key or encrypted file")
    except Exception as exc:
        logger.debug("Unhandled exception in _cipher_worker for task %s: %s", task_id, exc, exc_info=True)
        _finalize_task_failure(task_id, "An internal error occurred while processing the task")


def _queue_cipher_task(operation: str) -> tuple[Any, int]:
    """Validate a queue request and start a background worker."""
    _ensure_cleanup_thread_started()

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return _error_response("Request body must be a JSON object.", 400)

    try:
        key_path = _require_absolute_file_path(payload.get("key_path"), "key_path")
        file_paths = _normalize_file_paths(
            payload.get("file_path", payload.get("file_paths")),
            "file_path",
        )
    except ValueError as exc:
        logger.debug("Validation error in queue request: %s", exc)
        return _error_response("Invalid request payload", 400)

    # Security: ensure that all provided files are within the same directory
    # (or subdirectories) as the key to avoid processing arbitrary filesystem
    # locations supplied by untrusted clients.
    key_dir = key_path.parent
    for p in file_paths:
        if not _is_within_directory(p, key_dir):
            return _error_response("All file paths must be located under the key file's directory.", 400)

    task = _create_task(operation, key_path, file_paths)

    try:
        worker_thread = Thread(
            target=_cipher_worker,
            args=(task["task_id"], operation, key_path, file_paths),
            name=f"cipher-{operation}-worker-{task['task_id']}",
            daemon=False,
        )
        worker_thread.start()
    except Exception as exc:
        logger.debug("Failed to start worker thread for task %s: %s", task["task_id"], exc, exc_info=True)
        _finalize_task_failure(task["task_id"], "Failed to start background worker")
        return _error_response(
            "Could not start the background worker. The server may be under heavy load.",
            500,
        )

    response_body: dict[str, Any] = {
        "task_id": task["task_id"],
        "status": "queued",
        "operation": operation,
        "file_count": len(file_paths),
    }
    return jsonify(response_body), 202


@app.post("/api/key")
def create_key() -> tuple[Any, int]:
    """Create a Fernet key file on disk."""
    _ensure_cleanup_thread_started()

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return _error_response("Request body must be a JSON object.", 400)

    try:
        directory_path = _require_absolute_path(payload.get("directory_path"), "directory_path")
        file_name = _require_string(payload.get("file_name"), "file_name")
        key_path = _create_key_file(directory_path, file_name)
    except ValueError as exc:
        logger.debug("Validation error in create_key: %s", exc)
        return _error_response("Invalid request payload", 400)
    except OSError as exc:
        logger.debug("OS error creating key file: %s", exc, exc_info=True)
        return _error_response("Failed to create key file", 500)

    # Return only non-sensitive information about the created key.
    return (
        jsonify({"status": "created", "file_name": file_name}),
        201,
    )


@app.post("/api/encrypt")
def encrypt() -> tuple[Any, int]:
    """Queue a file encryption task."""
    return _queue_cipher_task("encrypt")


@app.post("/api/decrypt")
def decrypt() -> tuple[Any, int]:
    """Queue a file decryption task."""
    return _queue_cipher_task("decrypt")


@app.get("/api/task/<task_id>")
def task_status(task_id: str) -> tuple[Any, int]:
    """Get the current status of a queued cipher task."""
    _ensure_cleanup_thread_started()

    with jobs_lock:
        task = jobs.get(task_id)

    if task is None:
        return _error_response("Task not found.", 404)

    response_body: dict[str, Any] = {
        "task_id": task["task_id"],
        "operation": task["operation"],
        "status": task["status"],
    }

    if task["status"] == "completed":
        response_body["result"] = task.get("result", {})

    if task["status"] == "failed":
        response_body["error"] = task.get("error", "Unknown error")

    return jsonify(response_body), 200


@app.get("/api/health")
def api_health() -> tuple[Any, int]:
    """Report service health and task statistics."""
    _ensure_cleanup_thread_started()

    with jobs_lock:
        snapshot = list(jobs.values())

    counts = {
        "queued": 0,
        "in_progress": 0,
        "completed": 0,
        "failed": 0,
        "total": len(snapshot),
    }
    for task in snapshot:
        status = task.get("status")
        if status in counts:
            counts[status] += 1

    return (
        jsonify(
            {
                "status": "ok",
                "service": "Cipher",
                "bind": SERVICE_BIND_ADDRESS,
                "port": SERVICE_PORT,
                "task_counts": counts,
                "task_retention_minutes": TASK_RETENTION_MINUTES,
                "task_cleanup_interval_seconds": TASK_CLEANUP_INTERVAL_SECONDS,
                "cipher_algorithm": "fernet",
                "hostname": socket.gethostname(),
                "primary_ip": _get_primary_ip(),
                "local_ips": _collect_local_ip_addresses(),
            }
        ),
        200,
    )


if __name__ == "__main__":
    try:
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        )

        _initialize_service_config()
    except Exception as exc:
        logger.error(f"Failed to load configuration: {exc}")
        exit(1)

    _ensure_cleanup_thread_started()

    try:
        logger.info("=" * 50)
        logger.info("  Cipher API Server")
        logger.info("=" * 50)
        logger.info(f"Binding to: http://{SERVICE_BIND_ADDRESS}:{SERVICE_PORT}")
        logger.info("Threading: enabled")
        logger.info("Cipher Algorithm: fernet")
        logger.info(f"Task Retention: {TASK_RETENTION_MINUTES} minutes")
        logger.info(f"Cleanup Interval: {TASK_CLEANUP_INTERVAL_SECONDS} seconds")
        logger.info("Server starting...")

        app.run(
            host=SERVICE_BIND_ADDRESS,
            port=SERVICE_PORT,
            debug=False,
            threaded=True,
        )

    except KeyboardInterrupt:
        logger.info("=" * 50)
        logger.info("  Server Stopped")
        logger.info("=" * 50)

    except OSError as exc:
        if "Address already in use" in str(exc):
            logger.error(
                f"Port {SERVICE_PORT} is already in use. Change the port in resources/configuration.json"
            )
        elif "Permission denied" in str(exc):
            logger.error(
                f"Permission denied to bind to port {SERVICE_PORT}. On Linux/macOS, use a port >= 1024 or run with sudo."
            )
        else:
            logger.error(f"Network binding failed: {exc}")

    except Exception as exc:
        logger.error(f"Server startup failed: {exc}")
