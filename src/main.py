"""Cipher local web service."""

from __future__ import annotations

import ipaddress
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

import urllib.error
import urllib.request

from cryptography.fernet import Fernet, InvalidToken
from models import PostRequest, PostResponse
import struct
import tempfile
from flask import Flask, jsonify, request
import traceback
import shutil
import errno

logger = logging.getLogger(__name__)

CONFIG_PATH = Path(__file__).resolve().parent.parent / "resources" / "configuration.json"
SERVICE_BIND_ADDRESS = "127.0.0.1"
DEFAULT_SERVICE_PORT = 49158
SERVICE_PORT: int | None = None
ALLOWED_ROOTS: list[Path] = []
BLACKLISTED_ROOTS: list[Path] = []

SERVICEHANDLER_HASH: str | None = None

_config_cache: dict[str, Any] | None = None

_local_addresses_cache: set[str] | None = None
_local_addresses_cache_ts: float = 0.0
_LOCAL_ADDRESSES_CACHE_TTL: float = 300.0

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


def _get_local_device_addresses() -> set[str]:
    global _local_addresses_cache, _local_addresses_cache_ts
    now = time.time()
    if _local_addresses_cache is not None and (now - _local_addresses_cache_ts) < _LOCAL_ADDRESSES_CACHE_TTL:
        return _local_addresses_cache

    local_addresses: set[str] = set()
    candidate_names = {socket.gethostname(), socket.getfqdn()}

    for candidate_name in candidate_names:
        if not candidate_name:
            continue

        try:
            local_addresses.update(
                address_info[4][0]
                for address_info in socket.getaddrinfo(candidate_name, None)
            )
        except OSError:
            pass

        try:
            local_addresses.update(socket.gethostbyname_ex(candidate_name)[2])
        except OSError:
            pass

    for probe_address in ("8.8.8.8", "1.1.1.1"):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as socket_handle:
                socket_handle.connect((probe_address, 80))
                local_addresses.add(socket_handle.getsockname()[0])
        except OSError:
            pass

    normalized_addresses: set[str] = set()
    for address_value in local_addresses:
        try:
            normalized_addresses.add(ipaddress.ip_address(address_value).compressed)
        except ValueError:
            continue

    normalized_addresses.update({"127.0.0.1", "::1"})
    _local_addresses_cache = normalized_addresses
    _local_addresses_cache_ts = now
    return normalized_addresses


def _is_local_request() -> bool:
    remote_address = request.remote_addr
    if not isinstance(remote_address, str) or not remote_address.strip():
        return False

    try:
        client_ip = ipaddress.ip_address(remote_address.strip())
    except ValueError:
        return False

    if client_ip.is_loopback:
        return True

    return client_ip.compressed in _get_local_device_addresses()


@app.before_request
def restrict_to_local_device() -> tuple | None:
    if request.path.startswith("/api/") and not _is_local_request():
        return _error_response("Local device access only.", 403)

    return None


@app.after_request
def set_connection_header(response):
    content_type = response.headers.get("Content-Type", "")
    if content_type.startswith("text/html"):
        response.headers["Connection"] = "keep-alive"
    else:
        response.headers["Connection"] = "close"
    return response


def _options_response(allowed_methods: list[str]) -> tuple:
    """Return an OPTIONS response with allowed methods."""
    response = jsonify({})
    response.headers["Allow"] = ", ".join(allowed_methods)
    response.headers["Access-Control-Allow-Methods"] = ", ".join(allowed_methods)
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return response, 200


def _head_response() -> tuple:
    """Return a HEAD response with no body."""
    response = jsonify({})
    return response, 200


jobs_lock = Lock()
jobs: dict[str, dict[str, Any]] = {}

cleanup_lock = Lock()
cleanup_thread_started = False


def _utc_iso() -> str:
    """Return the current UTC time in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


def _load_configuration() -> dict[str, Any]:
    """Load configuration from resources/configuration.json (cached)."""
    global _config_cache
    if _config_cache is not None:
        return _config_cache

    if not CONFIG_PATH.exists():
        logger.debug("Configuration file missing: %s", CONFIG_PATH)
        raise FileNotFoundError("Configuration file not found. Ensure configuration.json exists.")

    try:
        with open(CONFIG_PATH, "r", encoding="utf-8-sig") as config_file:
            _config_cache = json.load(config_file)
    except json.JSONDecodeError as exc:
        logger.debug("Invalid JSON in configuration file %s: %s", CONFIG_PATH, exc)
        raise ValueError("Configuration file contains invalid JSON") from exc
    except Exception as exc:
        logger.debug("Failed to read configuration file %s: %s", CONFIG_PATH, exc)
        raise RuntimeError("Failed to read configuration file") from exc

    return _config_cache


def _is_within_any_directory(child: Path, parents: list[Path]) -> bool:
    """Return True if `child` is inside any of the `parents` (or equal), after resolving."""
    for parent in parents:
        if _is_within_directory(child, parent):
            return True
    return False


def _initialize_service_config() -> None:
    """Load and validate the service configuration."""
    global SERVICE_PORT
    global ALLOWED_ROOTS, BLACKLISTED_ROOTS

    config = _load_configuration()
    configured_port = config.get("port", DEFAULT_SERVICE_PORT)

    if isinstance(configured_port, str) and configured_port.isdigit():
        configured_port = int(configured_port)

    if not isinstance(configured_port, int):
        raise ValueError("port in configuration.json must be an integer")

    SERVICE_PORT = configured_port

    # Configure allowed file roots and blacklisted paths. Defaults are
    # intentionally conservative: allowed roots default to the repository
    # root, and blacklist defaults to empty (no blacklist).
    repo_root = Path(__file__).resolve().parent.parent
    allowed_roots = []
    cfg_allowed = config.get("allowed_roots")
    if isinstance(cfg_allowed, list) and cfg_allowed:
        for item in cfg_allowed:
            if not isinstance(item, str) or not item.strip():
                continue
            p = Path(item)
            if not p.is_absolute():
                p = (repo_root / p).resolve(strict=False)
            allowed_roots.append(p.resolve())
    else:
        # No allowed roots configured means "no allowlist"; leave empty
        # so blacklist (if present) is used as the only restriction.
        allowed_roots = []

    ALLOWED_ROOTS = allowed_roots
    # Parse blacklisted roots
    blacklist: list[Path] = []
    cfg_black = config.get("blacklisted_roots")
    if isinstance(cfg_black, list) and cfg_black:
        for item in cfg_black:
            if not isinstance(item, str) or not item.strip():
                continue
            p = Path(item)
            if not p.is_absolute():
                p = (repo_root / p).resolve(strict=False)
            blacklist.append(p.resolve())

    BLACKLISTED_ROOTS = blacklist


def _is_path_permitted(path: Path) -> bool:
    """Return True if `path` is permitted by the allowlist/blacklist policy.

    Policy:
    - If `ALLOWED_ROOTS` is non-empty: the path must be inside one of those roots.
    - Otherwise, if `BLACKLISTED_ROOTS` is non-empty: the path must NOT be inside any blacklisted root.
    - Otherwise: everything is permitted.
    """
    try:
        resolved = path.resolve()
    except Exception:
        # If we cannot resolve, deny for safety.
        return False

    if ALLOWED_ROOTS:
        return _is_within_any_directory(resolved, ALLOWED_ROOTS)

    if BLACKLISTED_ROOTS:
        return not _is_within_any_directory(resolved, BLACKLISTED_ROOTS)

    return True


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


def _require_boolean(payload: object, field_name: str) -> bool:
    """Extract a boolean field from a JSON payload."""
    if not isinstance(payload, bool):
        raise ValueError("Required boolean field is missing or invalid")
    return payload


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


def _normalize_output_paths(
    value: object,
    field_name: str,
    expected_count: int,
) -> list[Path] | None:
    """Normalize optional output file path(s) for a task request."""
    if value is None:
        return None

    if isinstance(value, str):
        values: list[object] = [value]
    elif isinstance(value, list):
        values = list(value)
    else:
        raise ValueError(f"{field_name} must be a string or list of strings")

    if not values:
        raise ValueError(f"{field_name} must contain at least one file path")

    if len(values) != expected_count:
        raise ValueError(f"{field_name} must include exactly one path per input file")

    normalized_paths: list[Path] = []
    for index, item in enumerate(values, start=1):
        output_path = _require_absolute_path(item, f"{field_name}[{index}]")
        parent = output_path.parent
        if not parent.exists() or not parent.is_dir():
            raise ValueError("Output directory does not exist")
        normalized_paths.append(output_path)

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


# Streaming format constants
# Magic header to identify files encrypted with chunked Fernet format
_CHUNKED_MAGIC = b"FRTN1"
# Use 1 MiB chunks by default for streaming to limit memory usage
_STREAM_CHUNK_SIZE = 1024 * 1024


def _stream_encrypt_file(source_path: Path, target_output_path: Path, fernet: Fernet) -> None:
    """Encrypt a file in streaming fashion and write to target_output_path.

    Format:
    - 5-byte magic: _CHUNKED_MAGIC
    - Repeated records: 8-byte big-endian token length, followed by token bytes
    """
    dirpath = target_output_path.parent
    dirpath.mkdir(parents=True, exist_ok=True)

    # write to a temp file in same directory then atomically rename
    with tempfile.NamedTemporaryFile(dir=str(dirpath), delete=False) as tmp:
        tmp_path = Path(tmp.name)
        tmp.write(_CHUNKED_MAGIC)

        with source_path.open("rb") as src:
            while True:
                chunk = src.read(_STREAM_CHUNK_SIZE)
                if not chunk:
                    break
                token = fernet.encrypt(chunk)
                tmp.write(struct.pack(">Q", len(token)))
                tmp.write(token)

    # final move with retries to handle Windows locks (OneDrive etc.).
    _replace_with_retries(tmp_path, target_output_path)


def _stream_decrypt_file(source_path: Path, target_output_path: Path, fernet: Fernet) -> None:
    """Decrypt a file written in the streaming chunked Fernet format."""
    dirpath = target_output_path.parent
    dirpath.mkdir(parents=True, exist_ok=True)

    with source_path.open("rb") as src:
        magic = src.read(len(_CHUNKED_MAGIC))
        if magic != _CHUNKED_MAGIC:
            # Not chunked format; fall back to attempting a single-token decrypt
            # to preserve compatibility with non-streamed files.
            src.seek(0)
            data = src.read()
            plaintext = fernet.decrypt(data)
            # write to temp then move
            with tempfile.NamedTemporaryFile(dir=str(dirpath), delete=False) as tmp:
                tmp_path = Path(tmp.name)
                tmp.write(plaintext)
            tmp_path.replace(target_output_path)
            return

        # Chunked format: read length-prefixed tokens
        with tempfile.NamedTemporaryFile(dir=str(dirpath), delete=False) as tmp:
            tmp_path = Path(tmp.name)
            while True:
                len_bytes = src.read(8)
                if not len_bytes:
                    break
                if len(len_bytes) != 8:
                    raise ValueError("Corrupt encrypted file: unexpected length header")
                (token_len,) = struct.unpack(">Q", len_bytes)
                token = src.read(token_len)
                if len(token) != token_len:
                    raise ValueError("Corrupt encrypted file: token truncated")
                plaintext = fernet.decrypt(token)
                tmp.write(plaintext)

    _replace_with_retries(tmp_path, target_output_path)


def _replace_with_retries(src: Path, dest: Path, attempts: int = 5, delay: float = 0.2) -> None:
    """Attempt to atomically replace dest with src, retrying on access errors.

    This helps on Windows where antivirus/OneDrive can transiently lock files.
    """
    last_exc: Exception | None = None
    for i in range(attempts):
        try:
            # Use os.replace via Path.replace which should be atomic where supported.
            src.replace(dest)
            return
        except PermissionError as exc:
            last_exc = exc
        except OSError as exc:
            # Map common access denied errno
            if getattr(exc, "winerror", None) == 5 or exc.errno in {errno.EACCES, errno.EPERM}:
                last_exc = exc
            else:
                raise

        try:
            os.replace(str(src), str(dest))
            return
        except Exception as exc:
            last_exc = exc

        # As another fallback, try copying the file contents then removing the temp
        try:
            shutil.copyfile(str(src), str(dest))
            src.unlink(missing_ok=True)
            return
        except Exception as exc:
            last_exc = exc

        time.sleep(delay)

    # If we reach here, all attempts failed; raise the last seen exception
    if last_exc:
        raise last_exc


def _safe_rename_with_retries(src: Path, dest: Path, attempts: int = 5, delay: float = 0.2) -> None:
    """Attempt to rename/move src to dest, with retries and copy fallback on Windows locks."""
    last_exc: Exception | None = None
    for i in range(attempts):
        try:
            src.replace(dest)
            return
        except Exception as exc:
            last_exc = exc

        try:
            os.replace(str(src), str(dest))
            return
        except Exception as exc:
            last_exc = exc

        # Fallback: copy contents then remove source
        try:
            shutil.copyfile(str(src), str(dest))
            src.unlink(missing_ok=True)
            return
        except Exception as exc:
            last_exc = exc

        time.sleep(delay)

    if last_exc:
        raise last_exc


def _encrypted_file_name(source_name: str, fernet: Fernet) -> str:
    """Encrypt a file name using the provided Fernet instance."""
    return fernet.encrypt(source_name.encode("utf-8")).decode("ascii")


def _decrypted_file_name(source_name: str, fernet: Fernet) -> str:
    """Decrypt a file name using the provided Fernet instance."""
    return fernet.decrypt(source_name.encode("ascii")).decode("utf-8")


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


def _cipher_worker(
    task_id: str,
    operation: str,
    key_path: Path,
    file_paths: list[Path],
    transform_file_name: bool,
    overwrite_source_file: bool,
    output_paths: list[Path] | None,
) -> None:
    """Process encryption or decryption work in the background."""
    with jobs_lock:
        jobs[task_id]["status"] = "in_progress"
        jobs[task_id]["updated_at"] = _utc_iso()

    try:
        fernet = _load_fernet(key_path)
        processed_files: list[dict[str, str]] = []

        if operation == "encrypt":
            _transform_name = _encrypted_file_name
            _process_file = _stream_encrypt_file
        elif operation == "decrypt":
            _transform_name = _decrypted_file_name
            _process_file = _stream_decrypt_file
        else:
            raise ValueError(f"Unsupported operation: {operation}")

        for index, source_path in enumerate(file_paths):
            requested_output_path = output_paths[index] if output_paths else None
            source_resolved = source_path.resolve(strict=False)

            if requested_output_path is not None:
                target_output_path = requested_output_path
            elif transform_file_name:
                output_name = _transform_name(source_path.name, fernet)
                target_output_path = _resolve_unique_path(source_path.parent, output_name)
            elif overwrite_source_file:
                target_output_path = source_path
            else:
                raise ValueError("Missing output file path for non-filename transformation")

            if overwrite_source_file:
                target_resolved = target_output_path.resolve(strict=False)
                if target_resolved != source_resolved and target_output_path.exists():
                    raise ValueError("Requested output path already exists")

                _process_file(source_path, source_path, fernet)

                if target_resolved != source_resolved:
                    _safe_rename_with_retries(source_path, target_output_path)
                    output_path = target_output_path
                else:
                    output_path = source_path
            else:
                if target_output_path.exists():
                    raise ValueError("Requested output path already exists")

                _process_file(source_path, target_output_path, fernet)
                output_path = target_output_path

            if transform_file_name:
                processed_files.append(
                    {
                        "input_path": str(source_resolved),
                        "output_path": str(output_path.resolve()),
                    }
                )
            else:
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
        with jobs_lock:
            jobs[task_id]["error_detail"] = str(exc)
        _finalize_task_failure(task_id, "Invalid Fernet key or encrypted file")
    except Exception as exc:
        tb = traceback.format_exc()
        logger.debug(
            "Unhandled exception in _cipher_worker for task %s: %s", task_id, exc, exc_info=True
        )
        with jobs_lock:
            jobs[task_id]["error_detail"] = str(exc)
            jobs[task_id]["traceback"] = tb
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
        transform_field_name = "encrypt_file_name" if operation == "encrypt" else "decrypt_file_name"
        transform_file_name = _require_boolean(payload.get(transform_field_name), transform_field_name)

        overwrite_raw = payload.get("overwrite_file", False)
        if not isinstance(overwrite_raw, bool):
            raise ValueError("overwrite_file must be a boolean")
        overwrite_source_file = overwrite_raw

        output_paths = _normalize_output_paths(
            payload.get("output_file_path", payload.get("output_file_paths")),
            "output_file_path",
            len(file_paths),
        )

        if not transform_file_name and not overwrite_source_file and output_paths is None:
            raise ValueError(
                "output_file_path is required when filename transformation is disabled and overwrite_file is false"
            )
    except ValueError as exc:
        logger.debug("Validation error in queue request: %s", exc)
        return _error_response("Invalid request payload", 400)
    # Enforce policy: key_path, input and output paths must be permitted
    # according to allowlist/blacklist rules configured in `configuration.json`.
    if not _is_path_permitted(key_path):
        return _error_response("Provided key_path is not permitted by server policy.", 400)

    for p in file_paths:
        if not _is_path_permitted(p):
            return _error_response("All file paths must be permitted by server policy.", 400)

    # Pre-resolve all paths once to avoid repeated filesystem calls
    try:
        key_resolved = key_path.resolve(strict=False)
    except Exception:
        key_resolved = key_path

    file_paths_resolved = []
    for p in file_paths:
        try:
            file_paths_resolved.append(p.resolve(strict=False))
        except Exception:
            file_paths_resolved.append(p)

    output_paths_resolved = None
    if output_paths:
        output_paths_resolved = []
        for out in output_paths:
            try:
                output_paths_resolved.append(out.resolve(strict=False))
            except Exception:
                output_paths_resolved.append(out)

        for source_resolved, output_resolved in zip(file_paths_resolved, output_paths_resolved):
            if not _is_path_permitted(output_resolved):
                return _error_response(
                    "All output file paths must be permitted by server policy.",
                    400,
                )
            if not overwrite_source_file and output_resolved == source_resolved:
                return _error_response(
                    "output_file_path cannot match the input file path unless overwrite_file is true.",
                    400,
                )

    # SECURITY: Prevent the provided key file from being processed as an
    # input or output file. Encrypting or decrypting the key file itself
    # would corrupt the key material and is not allowed.
    for p_resolved in file_paths_resolved:
        if p_resolved == key_resolved:
            return _error_response("The key file may not be used as an input file.", 400)

    if output_paths_resolved:
        for out_resolved in output_paths_resolved:
            if out_resolved == key_resolved:
                return _error_response("The key file may not be used as an output file.", 400)

    task = _create_task(operation, key_path, file_paths)

    try:
        worker_thread = Thread(
            target=_cipher_worker,
            args=(
                task["task_id"],
                operation,
                key_path,
                file_paths,
                transform_file_name,
                overwrite_source_file,
                output_paths,
            ),
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


@app.route("/api/key", methods=["POST", "HEAD", "OPTIONS"])
def create_key() -> tuple[Any, int]:
    """Create a Fernet key file on disk."""
    if request.method == "OPTIONS":
        return _options_response(["POST", "HEAD", "OPTIONS"])
    if request.method == "HEAD":
        return _head_response()

    _ensure_cleanup_thread_started()

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return _error_response("Request body must be a JSON object.", 400)

    try:
        # Create a key file at the requested directory (or repo root if
        # omitted). The chosen directory must be permitted by the server
        # policy (allowed roots / blacklist).
        file_name = _require_string(payload.get("file_name"), "file_name")
        provided_dir = payload.get("directory_path")
        repo_root = Path(__file__).resolve().parent.parent
        if provided_dir is None:
            directory_path = repo_root
        else:
            directory_path = _require_absolute_path(provided_dir, "directory_path")

        if not _is_path_permitted(directory_path):
            raise ValueError("directory_path is not permitted by server policy")

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


@app.route("/api/encrypt", methods=["POST", "HEAD", "OPTIONS"])
def encrypt() -> tuple[Any, int]:
    """Queue a file encryption task."""
    if request.method == "OPTIONS":
        return _options_response(["POST", "HEAD", "OPTIONS"])
    if request.method == "HEAD":
        return _head_response()
    return _queue_cipher_task("encrypt")


@app.route("/api/decrypt", methods=["POST", "HEAD", "OPTIONS"])
def decrypt() -> tuple[Any, int]:
    """Queue a file decryption task."""
    if request.method == "OPTIONS":
        return _options_response(["POST", "HEAD", "OPTIONS"])
    if request.method == "HEAD":
        return _head_response()
    return _queue_cipher_task("decrypt")


@app.route("/api/task/<task_id>", methods=["GET", "HEAD", "OPTIONS"])
def task_status(task_id: str) -> tuple[Any, int]:
    """Get the current status of a queued cipher task."""
    if request.method == "OPTIONS":
        return _options_response(["GET", "HEAD", "OPTIONS"])
    if request.method == "HEAD":
        return _head_response()

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
        # Provide a short error detail for debugging local failures.
        if "error_detail" in task:
            response_body["error_detail"] = task.get("error_detail")
        # Return 500 for failed tasks so HTTP clients can detect failures.
        return jsonify(response_body), 500

    return jsonify(response_body), 200


@app.route("/api/health", methods=["GET", "HEAD", "OPTIONS"])
def api_health() -> tuple[Any, int]:
    """Report service health and task statistics."""
    if request.method == "OPTIONS":
        return _options_response(["GET", "HEAD", "OPTIONS"])
    if request.method == "HEAD":
        return _head_response()

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
                "bind_address": SERVICE_BIND_ADDRESS,
                "port": SERVICE_PORT,
                "hostname": socket.gethostname(),
                "pid": os.getpid(),
                "task_counts": counts,
                "task_retention_minutes": TASK_RETENTION_MINUTES,
                "task_cleanup_interval_seconds": TASK_CLEANUP_INTERVAL_SECONDS,
                "cipher_algorithm": "fernet",
            }
        ),
        200,
    )


def _send_post_request(request: PostRequest) -> PostResponse:
    """Send a POST request and return a normalized response."""
    try:
        req = urllib.request.Request(
            request.url,
            data=request.body,
            headers=request.headers,
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=request.timeout) as resp:
            body = resp.read().decode("utf-8")
            return PostResponse(
                status_code=resp.status,
                reason=resp.reason,
                body=body,
                body_size=len(body),
                headers=dict(resp.headers),
                json_body=json.loads(body) if body else None,
            )
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        return PostResponse(
            status_code=exc.code,
            reason=exc.reason,
            body=body,
            body_size=len(body),
            headers=dict(exc.headers),
            json_body=json.loads(body) if body else None,
        )


def _register_endpoints_with_servicehandler() -> None:
    """Register this service's API endpoints with ServiceHandler."""
    global SERVICEHANDLER_HASH
    if not SERVICEHANDLER_HASH:
        return

    try:
        config = _load_configuration()
    except Exception:
        config = {}
    sh_port = config.get("servicehandlerPort", 49155)

    endpoints = [
        {
            "verb": "POST",
            "path": "/api/key",
            "path_variables": [],
            "body_schema": {
                "type": "object",
                "properties": {
                    "directory_path": {"type": "string", "description": "Absolute path to an existing directory for the key file."},
                    "file_name": {"type": "string", "description": "File name for the key (not a path)."}
                },
                "required": ["file_name"]
            },
            "description": "Create a new Fernet key file.",
        },
        {
            "verb": "POST",
            "path": "/api/encrypt",
            "path_variables": [],
            "body_schema": {
                "type": "object",
                "properties": {
                    "key_path": {"type": "string", "description": "Absolute path to existing key file."},
                    "file_path": {"type": "string", "description": "Absolute path of file to encrypt."},
                    "encrypt_file_name": {"type": "boolean", "description": "Encrypt the file name itself."}
                },
                "required": ["key_path", "file_path", "encrypt_file_name"]
            },
            "description": "Queue an encryption task to run in the background.",
        },
        {
            "verb": "POST",
            "path": "/api/decrypt",
            "path_variables": [],
            "body_schema": {
                "type": "object",
                "properties": {
                    "key_path": {"type": "string", "description": "Absolute path to existing key file."},
                    "file_path": {"type": "string", "description": "Absolute path of file to decrypt."},
                    "decrypt_file_name": {"type": "boolean", "description": "Decrypt the file name itself."}
                },
                "required": ["key_path", "file_path", "decrypt_file_name"]
            },
            "description": "Queue a decryption task to run in the background.",
        },
        {
            "verb": "GET",
            "path": "/api/task/<task_id>",
            "path_variables": ["task_id"],
            "body_schema": {},
            "description": "Return the current status and result of a queued cipher task.",
        },
        {
            "verb": "GET",
            "path": "/api/health",
            "path_variables": [],
            "body_schema": {},
            "description": "Service health check with task queue statistics.",
        },
    ]

    for ep in endpoints:
        try:
            request = PostRequest(
                url=f"http://127.0.0.1:{sh_port}/api/register/endpoint",
                body=json.dumps({"hash": SERVICEHANDLER_HASH, **ep}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
            response = _send_post_request(request)
            if response.status_code == 201:
                logger.info(f"Registered endpoint: {ep['verb']} {ep['path']}")
            elif response.status_code == 409:
                logger.debug(f"Endpoint already registered: {ep['verb']} {ep['path']}")
            else:
                logger.warning(f"Failed to register endpoint {ep['verb']} {ep['path']} (HTTP {response.status_code})")
        except Exception as exc:
            logger.warning(f"Failed to register endpoint {ep['verb']} {ep['path']}: {exc}")


def _servicehandler_keepalive_forever() -> None:
    global SERVICEHANDLER_HASH
    try:
        config = _load_configuration()
    except Exception:
        config = {}
    ph_port = config.get("servicehandlerPort", 49155)
    service_name = "Cipher"

    while True:
        time.sleep(15)
        try:
            request = PostRequest(
                url=f"http://127.0.0.1:{ph_port}/api/question/service",
                body=json.dumps({"name": service_name}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
            response = _send_post_request(request)
            if response.status_code == 200:
                continue
            if response.status_code != 404:
                logger.warning(f"ServiceHandler question failed (HTTP {response.status_code})")
                continue
        except Exception as exc:
            logger.warning(f"ServiceHandler question failed: {exc}")
            continue

        try:
            request = PostRequest(
                url=f"http://127.0.0.1:{ph_port}/api/register/service",
                body=json.dumps({
                    "name": service_name,
                    "port": SERVICE_PORT,
                    "starting_script": str(Path(__file__).resolve().parent.parent / "scripts" / ("run.bat" if os.name == "nt" else "run.sh")),
                    "bind_address": SERVICE_BIND_ADDRESS,
                    "hostname": socket.gethostname(),
                }).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
            response = _send_post_request(request)
            if response.status_code == 201 and isinstance(response.json_body, dict):
                SERVICEHANDLER_HASH = response.json_body.get("hash")
                logger.info(f"Registered with ServiceHandler, hash={SERVICEHANDLER_HASH[:16]}...")
                if SERVICEHANDLER_HASH:
                    _register_endpoints_with_servicehandler()
        except Exception as exc:
            logger.warning(f"ServiceHandler registration attempt failed: {exc}")


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

    config = _load_configuration()
    if config.get("servicehandlerEnabled", True):
        servicehandler_thread = Thread(
            target=_servicehandler_keepalive_forever,
            name="servicehandler-keepalive",
            daemon=True,
        )
        servicehandler_thread.start()

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
