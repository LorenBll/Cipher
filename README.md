# Cipher

Cipher is a local file encryption and decryption service. It solves the problem of safely creating Fernet keys and processing file encryption or decryption jobs through a small HTTP API.

## About
Cipher is scoped to local file operations and keeps task state in memory while background workers process queued jobs. The service binds to `127.0.0.1` on port `49160`, so it is intended for local-only use on the machine where it is running.

## Setup
1. Install the Python dependencies with `pip install -r requirements.txt`.
2. Review `resources/configuration.json` to configure `port`, `allowed_roots`, and `blacklisted_roots`.
		- `allowed_roots`: list of root paths the API is allowed to operate inside. If this list is non-empty, ONLY these roots are permitted and the blacklist is ignored.
		- `blacklisted_roots`: list of root paths that are forbidden when `allowed_roots` is empty. If `allowed_roots` is empty and `blacklisted_roots` is non-empty, any path inside a blacklisted root is forbidden.
		- Behavior summary:
			- If `allowed_roots` is non-empty → only those roots are permitted (blacklist ignored).
			- Else if `blacklisted_roots` is non-empty → all paths are permitted except any inside a blacklisted root.
			- Else (both lists empty) → all paths on the system are permitted.

		Example `resources/configuration.json`:
		```json
		{
			"port": 49160,
			"allowed_roots": [],
			"blacklisted_roots": []
		}
		```
3. Leave the project structure intact so the service can find `resources/` and `src/`.

## Run
1. Windows: run `scripts\run.bat`.
2. Unix-like systems: run `bash scripts/run.sh`.
3. Manual: run `python src/main.py` from the project root.

## API Endpoints

### `POST /api/key`
Creates a new Fernet key file.

- Body (JSON object):
  	- `directory_path` (string, optional): absolute path to an existing directory where the key file should be created. If omitted, defaults to the repository root. The chosen directory must be permitted by the server policy (`allowed_roots` / `blacklisted_roots`).
 	- `file_name` (string, required): file name only (not a path). Must not already exist in `directory_path`.
- Returns:
 	- `201` -> `{ "status": "created", "file_name": "mykey.key" }`
 	- `400` -> `{ "error": "Request body must be a JSON object." }`
 	- `400` -> `{ "error": "<validation-message>" }`
 	- `500` -> `{ "error": "Failed to create key file" }`

### `POST /api/encrypt`
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

### `POST /api/decrypt`
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

### `GET /api/task/<task_id>`
Returns current task state and final result/error once finished.

- Path parameters:
	- `task_id` (string, required): task identifier returned by `POST /api/encrypt` or `POST /api/decrypt`.
- Returns:
	- `200` ->
		```json
		{
			"task_id": "<uuid>",
			"operation": "encrypt",
			"status": "queued|in_progress|completed|failed",
			"result": {
				"operation": "encrypt",
				"file_count": 1,
				"files": [
					{ "input_name": "...", "output_name": "..." }
				]
			},
			"error": "<failure-reason>"
		}
		```
		Notes: `result` is present only for completed tasks; `error` only for failed tasks. When `encrypt_file_name` or `decrypt_file_name` is `true`, each file entry uses `input_path` and `output_path` with absolute paths instead of the name-only fields.
		When filename transformation is disabled, each file entry still returns `input_name` and `output_name`; `output_name` matches the requested output file name or the final renamed file when `overwrite_file` is used.
	- `404` -> `{ "error": "Task not found." }`

### `GET /api/health`
Service and queue health snapshot.

- Body: none
- Returns:
	- `200` ->
		```json
		{
			"status": "ok",
			"service": "Cipher",
			"bind_address": "127.0.0.1",
			"port": 49160,
			"task_counts": {
				"queued": 0,
				"in_progress": 0,
				"completed": 0,
				"failed": 0,
				"total": 0
			},
			"task_retention_minutes": 60,
			"task_cleanup_interval_seconds": 60,
			"cipher_algorithm": "fernet",
			"hostname": "...",
			"primary_ip": "...",
			"local_ips": ["..."]
		}
		```

## License
- [LICENSE](LICENSE)

## Author
- [LorenBll](https://github.com/LorenBll)