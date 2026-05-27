# Cipher

Cipher is a local file encryption and decryption service. It solves the problem of safely creating Fernet keys and processing file encryption or decryption jobs through a small HTTP API.

## About
Cipher is scoped to local file operations and keeps task state in memory while background workers process queued jobs. The service binds to `127.0.0.1` on port `49160`, so it is intended for local-only use on the machine where it is running.

## Setup
1. Install the Python dependencies with `pip install -r requirements.txt`.
2. Review `resources/configuration.json` if you want to change the port.
3. Leave the project structure intact so the service can find `resources/` and `src/`.

## Run
1. Windows: run `scripts\run.bat`.
2. Unix-like systems: run `bash scripts/run.sh`.
3. Manual: run `python src/main.py` from the project root.

## API Endpoints
- `POST /api/key` - Create a Fernet key file at a given absolute directory path.
- `POST /api/encrypt` - Queue one or more file paths for encryption.
- `POST /api/decrypt` - Queue one or more file paths for decryption.
- `GET /api/task/<task_id>` - Check the status or result of a queued task.
- `GET /api/health` - Return service health and task statistics.

## License
- [LICENSE](LICENSE)

## Author
- [LorenBll](https://github.com/LorenBll)