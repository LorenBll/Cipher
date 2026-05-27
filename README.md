# Cipher

Cipher is a local Flask service for Fernet-based file encryption and decryption. It validates single or batch encryption/decryption requests, runs background tasks, and exposes task status through polling.

## About

- Scope: local file key generation, encryption, and decryption.
- Runtime model: synchronous key creation, queued worker tasks for encrypt and decrypt.
- Networking: local-only bind (`127.0.0.1`) with health and task-status endpoints.

## Setup

### Prerequisites

- Python 3.10 or newer

### Install Dependencies

```bash
python -m pip install -r requirements.txt
```

### Configuration

Edit `resources/configuration.json` as needed:

- `port`: TCP port used by the service

## Run

Start with:

```bash
python src/main.py
```

Windows shortcut:

```bat
scripts\run.bat
```

Startup behavior is consistent with the other services in this workspace: structured logging and a threaded Flask server.

## Usage

### `POST /api/key`

- Method: `POST`
- Input: JSON with `directory_path` and `file_name`
- Behavior: validates destination and creates a new Fernet key file without returning key material
- Response: `201 Created` with destination metadata

### `POST /api/encrypt`

- Method: `POST`
- Input: JSON with `key_path` and `file_path` or `file_paths`
- Behavior: validates input files and queues encryption as a background task
- Response: `202 Accepted` with `task_id`

### `POST /api/decrypt`

- Method: `POST`
- Input: JSON with `key_path` and `file_path` or `file_paths`
- Behavior: validates input files and queues decryption as a background task
- Response: `202 Accepted` with `task_id`

### `GET /api/task/<task_id>`

- Method: `GET`
- Input: path parameter `task_id`
- Behavior: returns task state and result or error details when available
- Response: `200 OK`

### `GET /api/health`

- Method: `GET`
- Input: none
- Behavior: reports service and task health with local networking details
- Response: `200 OK` with `status`, `service`, `bind`, `port`, `task_counts`, `task_retention_minutes`, `task_cleanup_interval_seconds`, `cipher_algorithm`, `hostname`, `primary_ip`, and `local_ips`

## Project Structure

```text
Cipher/
├── deployment/
├── resources/
│   └── configuration.json
├── scripts/
├── src/
│   ├── main.py
│   └── models/
├── README.md
└── requirements.txt
```

## License

This repository does not include a license file.
