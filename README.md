# Cipher

Cipher is a local file encryption and decryption service. It solves the problem of safely creating Fernet keys and processing file encryption or decryption jobs through a small HTTP API.

## About
Cipher is scoped to local file operations and keeps task state in memory while background workers process queued jobs. The service binds to `127.0.0.1` on port `49158`, so it is intended for local-only use on the machine where it is running.

Cipher also supports processing very large files without loading them fully into memory. When encrypting or decrypting large files the service streams data in 1 MiB chunks and writes a chunked Fernet format to disk. This chunked layout begins with a small magic header (`FRTN1`) followed by a sequence of length-prefixed Fernet tokens; the server will still decrypt legacy single-token files produced by older versions.

## Integration

This service can optionally register with [ServiceHandler](https://www.github.com/LorenBll/ServiceHandler) for service discovery, but does not depend on it. Set `servicehandlerEnabled` in `resources/configuration.json` to control this behavior.

## Setup
1. Install dependencies: run `scripts\setup.bat` (Windows) or `bash scripts/setup.sh` (Unix), or manually `pip install -r requirements.txt`.
2. Review `resources/configuration.json` to configure `port`, `servicehandlerEnabled`, `servicehandlerPort`, `allowed_roots`, and `blacklisted_roots`.
		- `allowed_roots`: list of root paths the API is allowed to operate inside. If this list is non-empty, ONLY these roots are permitted and the blacklist is ignored.
		- `blacklisted_roots`: list of root paths that are forbidden when `allowed_roots` is empty. If `allowed_roots` is empty and `blacklisted_roots` is non-empty, any path inside a blacklisted root is forbidden.
		- Behavior summary:
			- If `allowed_roots` is non-empty → only those roots are permitted (blacklist ignored).
			- Else if `blacklisted_roots` is non-empty → all paths are permitted except any inside a blacklisted root.
			- Else (both lists empty) → all paths on the system are permitted.

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
	3. Leave the project structure intact so the service can find `resources/` and `src/`.

## Run
1. Windows: run `scripts\run.bat`.
2. Unix-like systems: run `bash scripts/run.sh`.
3. Manual: run `python src/main.py` from the project root.

## Access Control

All `/api/*` endpoints are local-device only. Requests from non-local addresses are rejected with:
- `403` -> `{ "error": "Local device access only." }`
- All endpoints also support `HEAD` and `OPTIONS`.
- API responses use `Connection: close` (non-persistent connections).

## API Endpoints

### `POST /api/key` (also `HEAD`, `OPTIONS`)
Creates a new Fernet key file.

- Body (JSON object):
  	- `directory_path` (string, optional): absolute path to an existing directory where the key file should be created. If omitted, defaults to the repository root. The chosen directory must be permitted by the server policy (`allowed_roots` / `blacklisted_roots`).
 	- `file_name` (string, required): file name only (not a path). Must not already exist in `directory_path`.
- Returns:
 	- `201` -> `{ "status": "created", "file_name": "mykey.key" }`
 	- `400` -> `{ "error": "Request body must be a JSON object." }`
 	- `400` -> `{ "error": "<validation-message>" }`
 	- `500` -> `{ "error": "Failed to create key file" }`

### `POST /api/encrypt` (also `HEAD`, `OPTIONS`)
Queues one encryption task executed in a background thread.

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
	- `202` ->
		```json
		{
			"task_id": "<uuid>",
			"status": "queued",
			"operation": "encrypt",
			"file_count": 2
		}
		```
	- `400` -> `{ "error": "Request body must be a JSON object." }`
	- `400` -> `{ "error": "<validation-message>" }`
	- `500` -> `{ "error": "Could not start the background worker. The server may be under heavy load." }`

### `POST /api/decrypt` (also `HEAD`, `OPTIONS`)
Queues one decryption task executed in a background thread.

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
	- `202` ->
		```json
		{
			"task_id": "<uuid>",
			"status": "queued",
			"operation": "decrypt",
			"file_count": 1
		}
		```
	- `400` -> `{ "error": "Request body must be a JSON object." }`
	- `400` -> `{ "error": "<validation-message>" }`
	- `500` -> `{ "error": "Could not start the background worker. The server may be under heavy load." }`

### `GET /api/task/<task_id>` (also `HEAD`, `OPTIONS`)
Returns current task state and final result/error once finished.

- Path parameters:
	- `task_id` (string, required): task identifier returned by `POST /api/encrypt` or `POST /api/decrypt`.
- Returns:
	- `200` -> (for `queued`, `in_progress`)
		```json
		{
			"task_id": "<uuid>",
			"operation": "encrypt",
			"status": "queued|in_progress"
		}
		```
	- `200` -> (for `completed` tasks)
		```json
		{
			"task_id": "<uuid>",
			"operation": "encrypt",
			"status": "completed",
			"result": {
				"operation": "encrypt",
				"file_count": 1,
				"files": [
					{ "input_name": "...", "output_name": "..." }
				]
			}
		}
		```
	- `500` -> (for `failed` tasks)
		```json
		{
			"task_id": "<uuid>",
			"operation": "encrypt",
			"status": "failed",
			"error": "<failure-reason>",
			"error_detail": "<short exception message>"
		}
		```
				Notes:
				- `result` is present only for completed tasks; `error` (and `error_detail`) only for failed tasks.
				- When `encrypt_file_name` or `decrypt_file_name` is `true`, each file entry uses `input_path` and `output_path` with absolute paths instead of the name-only fields.
				- When filename transformation is disabled, each file entry returns `input_name` and `output_name`; `output_name` matches the requested output file name or the final renamed file when `overwrite_file` is used.
				- The `error_detail` field contains a short exception message intended to help debug local failures (for example, permission denied caused by file syncing software). It may contain non-sensitive filesystem info.

				Troubleshooting permission errors:
				- On Windows, background sync services (OneDrive) or antivirus can temporarily lock files and cause `Permission denied` when the server attempts to replace or rename files. If you see permission errors in `error_detail`:
					- Pause OneDrive or move the file to a non-synced folder and retry.
					- Alternatively, provide an explicit `output_file_path` instead of `overwrite_file`, or run the command against a copy of the file.
				- The server will retry atomic replaces and falls back to copy-based moves, but transient locks can still cause failures.
	- `404` -> `{ "error": "Task not found." }`

### `GET /api/health` (also `HEAD`, `OPTIONS`)
Service and queue health snapshot.

- Body: none
- Returns:
	- `200` ->
		```json
		{
			"status": "ok",
			"service": "Cipher",
			"bind_address": "127.0.0.1",
			"port": 49158,
			"hostname": "...",
			"task_counts": {
				"queued": 0,
				"in_progress": 0,
				"completed": 0,
				"failed": 0,
				"total": 0
			},
			"task_retention_minutes": 30,
			"task_cleanup_interval_seconds": 60,
			"cipher_algorithm": "fernet"
		}
		```

## Deployment

The `deployment/` directory contains platform-specific auto-start configurations:

- **macOS**: `deployment/com.service.plist` — launchd plist. Copy to `~/Library/LaunchAgents/` after updating paths.
- **Linux**: `deployment/service.service` — systemd unit. Copy to `/etc/systemd/system/` after updating the `User` and paths.
- **Windows**: `deployment/startup-windows.vbs` — startup script. Place in the Windows Startup folder (`shell:startup`) or schedule as a task.

---

## License
- [LICENSE](LICENSE)

## Author
- [LorenBll](https://github.com/LorenBll)