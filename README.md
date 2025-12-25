# OpenSSL Certificate Agent Service

This repository contains the backend service for an AI agent designed to manage SSL/TLS certificates. It wraps OpenSSL functionalities into a REST API, allowing an AI to generate Private Keys, CSRs, and Certificates securely.

## How It Works

Instead of passing sensitive certificate data through the LLM context window, this service handles the cryptographic operations locally.
1. The AI Agent sends a request (e.g., "Create a self-signed cert").
2. This service generates the files using OpenSSL.
3. The service returns a temporary **download link**.
4. The AI Agent presents this link to the user, allowing them to download the files directly from this server.

## Configuration

Before deploying, you must configure the application so that the generated download links are accessible to your users.

1. Open `docker-compose.yml`.
2. Locate the `BASE_URL` environment variable.
3. Set this value to the IP address or domain name of this server (e.g., `http://10.67.67.50:8000`).

## Deployment

To start the service using Docker Compose:

```bash
docker-compose up -d --build
```

The service will be available at port 8000. You can view the interactive API documentation at `http://<your-ip>:8000/docs`.

## Integration

To connect your AI Agent to this backend:

1. **OpenAPI Specification:** Use the provided `openapi.yaml` file to define the agent's tools. Ensure the `servers` URL in this file points to this backend.
2. **System Prompt:** Use the text in `system_prompt.md` to instruct the AI on how to handle the specific "download link" workflow and multi-step certificate operations.

## Security and Retention

Generated files (Keys, CSRs, Certificates) are stored temporarily on the server filesystem. A background process automatically deletes these files **60 minutes** after generation.