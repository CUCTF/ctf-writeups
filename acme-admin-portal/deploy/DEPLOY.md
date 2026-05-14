# ACME Internal Admin Portal — Deployment Guide

This document explains how to deploy the challenge environment using Docker.

---

## Requirements

- [Docker](https://docs.docker.com/get-docker/) installed and running
- Port `5000` available on the host machine

---

## Quick Start (Recommended)

### 1. Build the Docker image

From the `deploy/` directory, run:

```bash
docker build -t acme-portal .
```

### 2. Run the container

```bash
docker run -p 5000:5000 acme-portal
```

### 3. Access the portal

Open your browser and navigate to:

```
http://localhost:5000
```

The challenge is now live.

---

## Stopping the Container

```bash
# Find the running container
docker ps

# Stop it
docker stop <container_id>
```

Or press `Ctrl+C` if running in the foreground.

---

## Rebuilding After Changes

If you modify any source files:

```bash
docker build --no-cache -t acme-portal .
docker run -p 5000:5000 acme-portal
```

---

## Running Without Docker (Alternative)

If Docker is unavailable, you can run the app directly with Python 3.11+:

```bash
# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py
```

Then visit `http://localhost:5000`.

---

## What the Competitor Receives

Competitors are given:
- The challenge description (see `challenge_description/challenge.md`)
- Access to the running application (via URL or Docker)

Competitors are **NOT** given:
- Source code
- The solution or writeup
- Any hints beyond those in the challenge description

---

## Notes for Graders

- The flag is stored in `flag.txt` in the application root
- The flag is: `flag{internal_tools_should_not_use_shell_true}`
- The vulnerability is in the `/ping` endpoint — see `app.py` for the annotated vulnerable code
- The full solution and writeup are in the `solution/` directory
