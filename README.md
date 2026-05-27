# Cipher

Cipher is a local Flask service for Fernet-based file encryption and decryption. It binds only to loopback, reads its port from [resources/configuration.json](resources/configuration.json), and exposes queued background tasks for encryption and decryption.

## About

The runtime behavior is intentionally narrow:

- `POST /api/key` creates a Fernet key file on disk and does not return the key material.
- `POST /api/encrypt` queues encryption work for one file or a batch of files.
- `POST /api/decrypt` queues decryption work for one file or a batch of files.
- `GET /api/task/<task_id>` returns the state of an encryption or decryption task.
- `GET /api/health` reports service status, binding information, task counts, and local IP data.
- The service always binds to `127.0.0.1`.

## Setup

### Prerequisites

- Python 3.10 or newer

### Install Dependencies

```bash
python -m pip install -r requirements.txt
```

### Configuration

Edit [resources/configuration.json](resources/configuration.json) if you want to change the listening port.

- `port` controls the TCP port used by the service

## Run

Start the service with:

```bash
python src/main.py
```

On Windows, you can also use:

```bat
scripts\run.bat
```

## Usage

### `POST /api/key`

- **Request type:** `POST`
- **Arguments:** `directory_path` and `file_name`
- **What it does:** validates the destination directory, ensures the key file name does not already exist, and creates a new Fernet key file
- **How it answers:** returns `201 Created` with the created path and file name, but not the key contents

### `POST /api/encrypt`

- **Request type:** `POST`
- **Arguments:** `key_path` and `file_path` or `file_paths`
- **What it does:** validates the key file and queues encryption for a single file or a batch of files
- **How it answers:** returns `202 Accepted` with a `task_id`

### `POST /api/decrypt`

- **Request type:** `POST`
- **Arguments:** `key_path` and `file_path` or `file_paths`
- **What it does:** validates the key file and queues decryption for a single file or a batch of files
- **How it answers:** returns `202 Accepted` with a `task_id`

### `GET /api/task/<task_id>`

- **Request type:** `GET`
- **Arguments:** path parameter `task_id`
- **What it does:** returns the current state of a queued encryption or decryption task
- **How it answers:** returns `200 OK` with the task status, and result or error details when available

### `GET /api/health`

- **Request type:** `GET`
- **Arguments:** none
- **What it does:** reports service health, binding information, task counts, retention settings, and local IP information
- **How it answers:** returns `200 OK` with JSON containing `status`, `service`, `bind`, `port`, `task_counts`, `task_retention_minutes`, `task_cleanup_interval_seconds`, `cipher_algorithm`, `hostname`, `primary_ip`, and `local_ips`

The service starts with structured logging and a threaded Flask server, matching the same startup wrapper used by the other projects in this workspace.

## Project Structure

```text
Cipher/
├── deployment/
│   ├── com.service.plist
│   ├── service.service
│   └── startup-windows.vbs
├── resources/
│   └── configuration.json
├── scripts/
│   ├── run.bat
│   ├── run.sh
│   ├── setup.bat
│   └── setup.sh
├── src/
│   ├── main.py
│   └── models/
│       ├── __init__.py
│       ├── get_request.py
│       ├── get_response.py
│       ├── post_request.py
│       └── post_response.py
└── requirements.txt
```

## License

This repository does not include a license file.
