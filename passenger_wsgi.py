"""
Passenger WSGI entry point for DirectAdmin.
Self-bootstrapping: installs pip packages and collects static files
on the very first request, then starts Django normally from then on.
No SSH access required.
"""
import sys
import os
import subprocess
import traceback
from pathlib import Path

# ---------------------------------------------------------------------------
# Dynamic and configured paths
# ---------------------------------------------------------------------------
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))

# Virtualenv candidate paths for DirectAdmin / CloudLinux
VENV_CANDIDATES = [
    "/home/joyministries/virtualenv/domains/api.joyministries.co.za/public_html/3.11",
    os.path.expanduser("~/virtualenv/domains/api.joyministries.co.za/public_html/3.11"),
]

VENV_BASE = None
for candidate in VENV_CANDIDATES:
    if os.path.exists(candidate):
        VENV_BASE = candidate
        break

if not VENV_BASE:
    VENV_BASE = "/home/joyministries/virtualenv/domains/api.joyministries.co.za/public_html/3.11"

VENV_SITE_PACKAGES = os.path.join(VENV_BASE, "lib", "python3.11", "site-packages")
VENV_PYTHON        = os.path.join(VENV_BASE, "bin", "python3.11")
VENV_PIP           = os.path.join(VENV_BASE, "bin", "pip")

# Fallback if python3.11 binary name differs slightly
if not os.path.exists(VENV_PYTHON):
    alt_python = os.path.join(VENV_BASE, "bin", "python")
    if os.path.exists(alt_python):
        VENV_PYTHON = alt_python

# Flag file — created after bootstrap completes so it never runs again
BOOTSTRAP_DONE_FLAG = os.path.join(PROJECT_ROOT, ".bootstrap_done")
BOOTSTRAP_LOG = os.path.join(PROJECT_ROOT, "bootstrap.log")

# Pre-create logs directory so Django's RotatingFileHandler can always open files
LOGS_DIR = os.path.join(PROJECT_ROOT, "logs")
try:
    os.makedirs(LOGS_DIR, exist_ok=True)
except OSError:
    pass  # If it still fails, Django will fall back to console logging

# ---------------------------------------------------------------------------
# Add virtualenv and project to sys.path
# ---------------------------------------------------------------------------
for p in [VENV_SITE_PACKAGES, PROJECT_ROOT]:
    if os.path.exists(p) and p not in sys.path:
        sys.path.insert(0, p)

# ---------------------------------------------------------------------------
# Load environment variables from .env
# ---------------------------------------------------------------------------
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "leavesystem.settings")

try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(PROJECT_ROOT, ".env"))
except ImportError:
    pass  # dotenv not yet installed — bootstrap will install it

# ---------------------------------------------------------------------------
# ONE-TIME BOOTSTRAP — only runs if .bootstrap_done does not exist
# ---------------------------------------------------------------------------
bootstrap_error = None

if not os.path.exists(BOOTSTRAP_DONE_FLAG):
    try:
        def run(cmd, desc):
            """Run a shell command and log output."""
            with open(BOOTSTRAP_LOG, "a") as f:
                f.write(f"\n>>> {desc}\n$ {' '.join(cmd)}\n")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=PROJECT_ROOT,
            )
            with open(BOOTSTRAP_LOG, "a") as f:
                f.write(result.stdout)
                if result.returncode != 0:
                    f.write(f"STDERR: {result.stderr}\n")
            return result.returncode == 0

        with open(BOOTSTRAP_LOG, "w") as f:
            f.write("=== Bootstrap started ===\n")
            f.write(f"PROJECT_ROOT: {PROJECT_ROOT}\n")
            f.write(f"VENV_BASE: {VENV_BASE}\n")
            f.write(f"VENV_PYTHON: {VENV_PYTHON}\n")
            f.write(f"VENV_PIP: {VENV_PIP}\n\n")

        # Step 1: Install all pip dependencies
        requirements = os.path.join(PROJECT_ROOT, "requirements.txt")
        if os.path.exists(requirements):
            run([VENV_PIP, "install", "-r", requirements], "Installing requirements")

        # Step 2: Reload dotenv now that dotenv package is installed
        try:
            from dotenv import load_dotenv
            load_dotenv(os.path.join(PROJECT_ROOT, ".env"))
        except ImportError:
            pass

        # Step 3: Run migrations
        run([VENV_PYTHON, "manage.py", "migrate", "--no-input"], "Running database migrations")

        # Step 4: Collect static files for WhiteNoise + Django admin
        run([VENV_PYTHON, "manage.py", "collectstatic", "--no-input"], "Collecting static files")

        # Step 5: Create media directory for uploaded documents
        media_dir = os.path.join(PROJECT_ROOT, "media", "leave_documents")
        os.makedirs(media_dir, exist_ok=True)

        # Step 6: Mark bootstrap as complete
        with open(BOOTSTRAP_DONE_FLAG, "w") as f:
            f.write("Bootstrap complete. Delete this file to re-run bootstrap.\n")

        with open(BOOTSTRAP_LOG, "a") as f:
            f.write("\n=== Bootstrap complete ===\n")

    except Exception as e:
        bootstrap_error = traceback.format_exc()
        try:
            with open(BOOTSTRAP_LOG, "a") as f:
                f.write(f"\nBOOTSTRAP EXCEPTION:\n{bootstrap_error}\n")
        except Exception:
            pass

# ---------------------------------------------------------------------------
# Start Django WSGI with diagnostic fallback
# ---------------------------------------------------------------------------
django_init_error = None
try:
    try:
        import pymysql
        pymysql.install_as_MySQLdb()
    except ImportError:
        pass

    from django.core.wsgi import get_wsgi_application
    application = get_wsgi_application()
except Exception as e:
    django_init_error = traceback.format_exc()

    def error_application(environ, start_response):
        """Display clear diagnostic error in browser instead of opaque 500 error."""
        log_content = ""
        if os.path.exists(BOOTSTRAP_LOG):
            try:
                with open(BOOTSTRAP_LOG, "r") as f:
                    log_content = f.read()
            except Exception:
                log_content = "Could not read bootstrap.log"

        error_html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Application Startup Error</title>
    <style>
        body {{ font-family: monospace; background: #0f172a; color: #f8fafc; padding: 2rem; }}
        h1 {{ color: #ef4444; border-bottom: 2px solid #ef4444; padding-bottom: 0.5rem; }}
        h2 {{ color: #f59e0b; margin-top: 1.5rem; }}
        pre {{ background: #1e293b; padding: 1rem; border-radius: 6px; overflow-x: auto; color: #38bdf8; }}
        .box {{ background: #1e293b; border-left: 4px solid #ef4444; padding: 1rem; margin-bottom: 1rem; }}
    </style>
</head>
<body>
    <h1>Django Startup Failed (500 Error Diagnostic)</h1>
    <div class="box">
        <strong>Error during Django WSGI initialization:</strong>
        <pre>{django_init_error}</pre>
    </div>
    {"<div class='box'><strong>Error during Bootstrap:</strong><pre>" + bootstrap_error + "</pre></div>" if bootstrap_error else ""}
    <h2>System Information</h2>
    <pre>PROJECT_ROOT: {PROJECT_ROOT}
VENV_BASE: {VENV_BASE}
sys.executable: {sys.executable}
sys.path:
{chr(10).join(sys.path)}</pre>
    <h2>Bootstrap Log (last output)</h2>
    <pre>{log_content or "No bootstrap log available."}</pre>
</body>
</html>"""
        start_response('500 Internal Server Error', [
            ('Content-Type', 'text/html; charset=utf-8'),
            ('Content-Length', str(len(error_html.encode('utf-8'))))
        ])
        return [error_html.encode('utf-8')]

    application = error_application

