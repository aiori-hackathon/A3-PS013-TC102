# TraceForge Deployment Checklist

TraceForge is packaged for local evaluation and academic submission. This checklist is a deployment baseline, not a certification.

## Before running outside localhost

- Set `APP_ENV=production` and provide `APP_SECRET_KEY` through the deployment secret manager. Never commit `.env` or copy a real secret into reports or screenshots.
- Use a production ASGI process without `--reload`, bound to a private interface behind a correctly configured HTTPS reverse proxy. Do not expose the development server directly to the public internet.
- Restrict access to the data directory. It contains original evidence, generated reports, the SQLite database, and the local development secret if one was created. Apply least-privilege filesystem permissions and encrypted backups.
- Test backup restoration, retention/deletion procedures, incident response, and access to report downloads before accepting real evidence.
- Add rate limiting and account lifecycle controls before public exposure. Review token lifetime and session revocation requirements for the intended environment.
- Establish a documented process for database schema migrations. The included startup migration is intentionally additive for the SQLite starter schema; it is not a substitute for a full migration framework for a production service.
- Configure reverse-proxy request-body limits to match application upload limits and confirm timeout behavior for large evidence files/reports.
- Use synthetic logs to run the security matrix and browser workflow checks after deployment.
- Keep source evidence collection details and chain-of-custody records outside the claims made by the application unless those processes are independently implemented and validated.

## Suggested local run

From the extracted project directory in Windows CMD:

```bat
.venv\Scripts\activate.bat
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

This command intentionally binds to loopback. For remote access, use a properly secured deployment configuration rather than changing the bind address without a proxy, firewall, TLS, and operational controls.
