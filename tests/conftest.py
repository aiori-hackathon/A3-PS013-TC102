"""Test-only environment defaults; never used by the running application."""
import os

# Keep test runs deterministic without creating a developer's local secret file.
os.environ.setdefault("APP_SECRET_KEY", "test-only-secret-key-not-for-any-deployment-123456789")
