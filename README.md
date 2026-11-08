# Sovereign Core

Sovereign Core is a modular AI runtime designed with security, privacy, and local-first operation in mind.

## Features

- Modular runtime architecture
- Security-focused egress guard
- CLI and chat launchers
- Adversarial and regression test suite
- Unicode character-property reference data

## Requirements

- Python 3
- Termux or a Unix-like environment

## Usage

Run the CLI:

python sovereign_cli.py

Run the chat launcher:

python chat_launcher.py

Run the test suite:

python -m pytest

## Security

This project includes an egress guard designed to detect and redact potential secrets before they leave the local environment. Do not store real API keys, tokens, passwords, or private keys in the repository.

## License

MIT
