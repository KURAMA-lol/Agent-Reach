"""Authenticated HTTP adapter for Agent Reach on Vercel.

Only upstream read/search actions declared by Agent Reach are exposed.
No arbitrary shell, install, login, browser, or configuration commands run here.
"""
from __future__ import annotations

import hmac
import json
import os
import subprocess
import sys

from flask import Flask, jsonify, request

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024


def authorized() -> bool:
    expected = os.environ.get("AGENT_REACH_API_TOKEN", "")
    supplied = request.headers.get("Authorization", "")
    if supplied.startswith("Bearer "):
        supplied = supplied[7:].strip()
    return bool(expected) and hmac.compare_digest(supplied, expected)


def error(message: str, status: int):
    return jsonify({"ok": False, "error": message}), status


def run_cli(argv: list[str], timeout: int = 45):
    env = os.environ.copy()
    env.setdefault("HOME", "/tmp")
    env.setdefault("XDG_CONFIG_HOME", "/tmp/.config")
    # Vercel adds function dependency directories to this process's sys.path.
    # A child Python process does not inherit sys.path automatically, so pass
    # those paths through PYTHONPATH for the Agent Reach CLI subprocess.
    inherited_pythonpath = env.get("PYTHONPATH", "")
    python_paths = [p for p in sys.path if p]
    env["PYTHONPATH"] = os.pathsep.join(
        [inherited_pythonpath, *python_paths] if inherited_pythonpath else python_paths
    )
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "agent_reach.cli", *argv],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=timeout, env=env, check=False,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": {"code": "TIMEOUT", "message": "Agent Reach timed out."}}, 504
    except Exception as exc:
        return {"ok": False, "error": {"code": "EXECUTION_ERROR", "message": str(exc)}}, 500
    output = (proc.stdout or "").strip()
    try:
        payload = json.loads(output) if output else {
            "ok": False, "error": {"code": "EMPTY_OUTPUT", "message": (proc.stderr or "No output")[-2000:]},
        }
    except json.JSONDecodeError:
        payload = {"ok": False, "error": {"code": "INVALID_OUTPUT", "message": (output or proc.stderr)[-4000:]}}
    return payload, (200 if proc.returncode == 0 else 422)


@app.get("/")
@app.get("/health")
def health():
    return jsonify({
        "service": "Agent Reach API", "status": "online",
        "authentication": "Bearer token required for /read, /run and /channels",
        "endpoints": ["POST /read", "POST /run", "GET /channels", "GET /health"],
    })


@app.post("/read")
def read_url():
    if not authorized():
        return error("Unauthorized. Supply Authorization: Bearer <token>.", 401)
    body = request.get_json(silent=True) or {}
    url = body.get("url")
    if not isinstance(url, str) or not url.strip() or len(url) > 4096:
        return error("Body must contain a valid 'url' string (max 4096 characters).", 400)
    if not url.startswith(("https://", "http://")):
        return error("Only http:// and https:// URLs are accepted.", 400)
    payload, status = run_cli(["read", url.strip()])
    return jsonify(payload), status


@app.post("/run")
def run_action():
    if not authorized():
        return error("Unauthorized. Supply Authorization: Bearer <token>.", 401)
    body = request.get_json(silent=True) or {}
    channel_name, action_name = body.get("channel"), body.get("action")
    params = body.get("params", {})
    if not isinstance(channel_name, str) or not isinstance(action_name, str):
        return error("Body requires string fields 'channel' and 'action'.", 400)
    if not isinstance(params, dict):
        return error("'params' must be a JSON object.", 400)
    try:
        from agent_reach.channels import get_all_channels
        from agent_reach.runtime.dispatch import find_action
        channel = next((c for c in get_all_channels() if c.name == channel_name), None)
        action = find_action(channel, action_name) if channel else None
    except Exception as exc:
        return error(f"Could not load Agent Reach action registry: {exc}", 500)
    if channel is None or action is None:
        return error("Unknown channel/action. Use GET /channels to inspect available actions.", 404)
    allowed = {p.name: p for p in action.params}
    unknown = set(params) - set(allowed)
    if unknown:
        return error("Unknown parameter(s): " + ", ".join(sorted(unknown)), 400)
    argv = [channel_name, action_name]
    for name, spec in allowed.items():
        value = params.get(name)
        if value is None:
            if spec.required:
                return error(f"Missing required parameter: {name}", 400)
            continue
        if isinstance(value, bool):
            value = "true" if value else "false"
        elif isinstance(value, (str, int, float)):
            value = str(value)
        else:
            return error(f"Parameter '{name}' must be a string or number.", 400)
        if len(value) > 8000:
            return error(f"Parameter '{name}' is too long.", 400)
        if spec.required:
            argv.append(value)
        else:
            argv.extend([f"--{name}", value])
    backend = body.get("backend")
    if backend is not None:
        valid = {name for name, _ in action.backends}
        if action.public_web:
            valid.add("public-web")
        if not isinstance(backend, str) or backend not in valid:
            return error("Unsupported backend for this action.", 400)
        argv.extend(["--backend", backend])
    payload, status = run_cli(argv)
    return jsonify(payload), status


@app.get("/channels")
def channels():
    if not authorized():
        return error("Unauthorized. Supply Authorization: Bearer <token>.", 401)
    try:
        from agent_reach.channels import get_all_channels
        data = []
        for channel in get_all_channels():
            data.append({
                "name": channel.name, "description": channel.description, "level": channel.level,
                "actions": [{
                    "name": action.name, "help": action.help,
                    "params": [{"name": p.name, "required": p.required, "type": p.type.__name__, "help": p.help}
                               for p in action.params],
                    "backends": [name for name, _ in action.backends],
                    "public_web": list(action.public_web),
                } for action in channel.actions],
            })
        return jsonify({"ok": True, "channels": data})
    except Exception as exc:
        return error(f"Could not load channels: {exc}", 500)
