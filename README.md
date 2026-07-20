# Cipher

Cipher is a local file encryption and decryption service. It solves the problem of safely creating Fernet keys and processing file encryption or decryption jobs through a small HTTP API.

## About
Cipher is scoped to local file operations and keeps task state in memory while background workers process queued jobs. The service binds to `127.0.0.1` on port `49158` and rejects API calls that do not come from the local device.

**Features:**

- **Fernet Key Creation** — generate and save a Fernet symmetric key file to any permitted directory.
- **File Encryption / Decryption** — queue background encryption or decryption tasks for one or more files with a single API call.
- **Large File Streaming** — files are processed in 1 MiB chunks using a chunked Fernet format (`FRTN1` magic header), avoiding full memory load. Legacy single-token files are still supported on decryption.
- **Filename Transformation** — optionally encrypt or decrypt the file name itself, returning the obfuscated or restored name.
- **Overwrite Mode** — replace source files in-place with their encrypted or decrypted content.
- **Path Policy** — configurable allowlist and blacklist of root directories control which paths the API is permitted to operate on.
- **Background Task Cleanup** — finished tasks are automatically removed after a configurable retention period.
- **ServiceHandler Integration** — optionally registers with ServiceHandler for service discovery and endpoint registration.

> **Safety notice**: Cipher is intended only for local, trusted environments. The encryption key file must be kept safe; losing it makes encrypted data permanently unrecoverable.

## Setup
1. Install Python dependencies: `pip install -r requirements.txt`.
2. Review `resources/configuration.json` to configure `port`, `servicehandlerEnabled`, `servicehandlerPort`, `allowed_roots`, and `blacklisted_roots`. See below for the path policy behaviour.
3. Leave the project structure intact so the service can find `resources/` and `src/`.

### Path Policy
The path policy uses two lists in `resources/configuration.json`:
- `allowed_roots`: list of root paths the API is allowed to operate inside. If this list is non-empty, ONLY these roots are permitted and the blacklist is ignored.
- `blacklisted_roots`: list of root paths that are forbidden when `allowed_roots` is empty. If both lists are empty, all paths on the system are permitted.

Example `resources/configuration.json`:
```json
{
    "port": 49158,
    "servicehandlerEnabled": true,
    "servicehandlerPort": 49155,
    "allowed_roots": [],
    "blacklisted_roots": []
}
```

## Run
1. Windows: run `scripts\run.bat`.
2. Unix-like systems: run `bash scripts/run.sh`.
3. Manual: run `python src/main.py` from the project root.

## Access Control

All `/api/*` endpoints are local-device only. Requests from non-local addresses are rejected with:
- `403` -> `{ "error": "Local device access only." }`
- All endpoints also support `HEAD` and `OPTIONS`.
- API responses use `Connection: close`.

## API Endpoints

### `POST /api/key` (also `HEAD`, `OPTIONS`)
Creates a new Fernet key file.
- Auth: local-device only (no API key required)
- Body (JSON object):
	- `directory_path` (string, optional): absolute path to an existing directory where the key file should be created. If omitted, defaults to the repository root. The chosen directory must be permitted by the server policy (`allowed_roots` / `blacklisted_roots`).
	- `file_name` (string, required): file name only (not a path). Must not already exist in `directory_path`.
- Returns:
	- `201` -> `{ "status": "created", "file_name": "mykey.key" }`
	- `400` -> `{ "error": "Request body must be a JSON object." }`
	- `400` -> `{ "error": "Invalid request payload" }`
	- `500` -> `{ "error": "Failed to create key file" }`

### `POST /api/encrypt` (also `HEAD`, `OPTIONS`)
Queues one encryption task executed in a background thread.
- Auth: local-device only (no API key required)
- Body (JSON object):
	- `key_path` (string, required): absolute path to existing key file.
	- `file_path` (string or array of strings, required unless `file_paths` used): absolute path(s) of existing file(s) to encrypt.
	- `file_paths` (array of strings, optional alias): alternative to `file_path`.
	- `encrypt_file_name` (boolean, required): if `true`, encrypts the file name itself and returns the resulting absolute output path in the task result.
	- `overwrite_file` (boolean, optional, default `false`): if `true`, encrypted content is written into the source file before any optional rename.
	- `output_file_path` (string, optional unless required by rule below): absolute output file path for one input file.
	- `output_file_paths` (array of strings, optional alias): one absolute output file path per input file.
	- Requirement rule: when `encrypt_file_name` is `false` and `overwrite_file` is `false`, `output_file_path` or `output_file_paths` is required.
	- Output path safety: input, key and output paths must be permitted by the server policy defined by `allowed_roots` and `blacklisted_roots` in `resources/configuration.json`. If `allowed_roots` is non-empty, only paths inside those roots are permitted. If `allowed_roots` is empty but `blacklisted_roots` contains entries, any path inside a blacklisted root is forbidden. If both lists are empty, all paths are permitted. If `overwrite_file` is `false`, output paths must not already exist.
- Returns:
	- `202` -> `{ "task_id": "...", "status": "queued", "operation": "encrypt", "file_count": 1 }`
	- `400` -> `{ "error": "Request body must be a JSON object." }`
	- `400` -> `{ "error": "Invalid request payload" }`
	- `500` -> `{ "error": "Could not start the background worker. The server may be under heavy load." }`

### `POST /api/decrypt` (also `HEAD`, `OPTIONS`)
Queues one decryption task executed in a background thread.
- Auth: local-device only (no API key required)
- Body (JSON object):
	- `key_path` (string, required): absolute path to existing key file.
	- `file_path` (string or array of strings, required unless `file_paths` used): absolute path(s) of existing file(s) to decrypt.
	- `file_paths` (array of strings, optional alias): alternative to `file_path`.
	- `decrypt_file_name` (boolean, required): if `true`, decrypts the file name itself and returns the resulting absolute output path in the task result.
	- `overwrite_file` (boolean, optional, default `false`): if `true`, decrypted content is written into the source file before any optional rename.
	- `output_file_path` (string, optional unless required by rule below): absolute output file path for one input file.
	- `output_file_paths` (array of strings, optional alias): one absolute output file path per input file.
	- Requirement rule: when `decrypt_file_name` is `false` and `overwrite_file` is `false`, `output_file_path` or `output_file_paths` is required.
	- Output path safety: input, key and output paths must be permitted by the server policy defined by `allowed_roots` and `blacklisted_roots` in `resources/configuration.json`. If `allowed_roots` is non-empty, only paths inside those roots are permitted. If `allowed_roots` is empty but `blacklisted_roots` contains entries, any path inside a blacklisted root is forbidden. If both lists are empty, all paths are permitted. If `overwrite_file` is `false`, output paths must not already exist.
	- Note: the file referenced by `key_path` must not be included in the `file_path`/`file_paths` input or in `output_file_path`/`output_file_paths`. The server will reject requests that attempt to process the key file itself.
- Returns:
	- `202` -> `{ "task_id": "...", "status": "queued", "operation": "decrypt", "file_count": 1 }`
	- `400` -> `{ "error": "Request body must be a JSON object." }`
	- `400` -> `{ "error": "Invalid request payload" }`
	- `500` -> `{ "error": "Could not start the background worker. The server may be under heavy load." }`

### `GET /api/task/<task_id>` (also `HEAD`, `OPTIONS`)
Returns current task state and final result or error once finished.
- Auth: local-device only (no API key required)
- Path parameters:
	- `task_id` (string, required): task identifier returned by `POST /api/encrypt` or `POST /api/decrypt`.
- Returns:
	- `200` ->
		```json
		{
			"task_id": "<uuid>",
			"operation": "encrypt",
			"status": "queued|in_progress|completed",
			"result": {
				"operation": "encrypt",
				"file_count": 1,
				"files": [
					{ "input_name": "...", "output_name": "..." }
				]
			}
		}
		```
	- `500` ->
		```json
		{
			"task_id": "<uuid>",
			"operation": "encrypt",
			"status": "failed",
			"error": "<failure-reason>",
			"error_detail": "<short exception message>"
		}
		```
	- `404` -> `{ "error": "Task not found." }`
- Notes:
	- `result` is present only for completed tasks; `error` (and `error_detail`) only for failed tasks.
	- When `encrypt_file_name` or `decrypt_file_name` is `true`, each file entry uses `input_path` and `output_path` with absolute paths instead of the name-only fields.
	- When filename transformation is disabled, each file entry returns `input_name` and `output_name`.
	- `error_detail` contains a short exception message intended to help debug local failures (e.g., permission denied caused by file syncing software).

### `GET /api/health` (also `HEAD`, `OPTIONS`)
Service and queue health snapshot.
- Auth: local-device only (no API key required)
- Body: none
- Returns:
	- `200` -> `{ "status": "ok", "service": "Cipher", "bind_address": "127.0.0.1", "port": 49158, "hostname": "...", "pid": 12345, "task_counts": { "queued": 0, "in_progress": 0, "completed": 0, "failed": 0, "total": 0 }, "task_retention_minutes": 30, "task_cleanup_interval_seconds": 60, "cipher_algorithm": "fernet" }`

---

## Support
- Open an issue on [GitHub](https://github.com/LorenBll/Cipher/issues) for bug reports, feature requests, or help.

## License
- [LICENSE](LICENSE)

## Author
- [LorenBll](https://github.com/LorenBll)
