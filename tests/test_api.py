"""End-to-end API smoke tests for ownership and real report generation."""
import uuid
from fastapi.testclient import TestClient
from app.main import app


def register(client, email):
    response = client.post('/api/auth/register', json={"display_name":"Test User", "email":email, "password":"Test-Pass-123!"})
    assert response.status_code == 201, response.text
    return {"Authorization": "Bearer " + response.json()["access_token"]}


def test_evidence_ownership_upload_hash_and_reports():
    with TestClient(app) as client:
        assert client.get('/api/evidence').status_code == 401
        suffix = uuid.uuid4().hex
        headers_a = register(client, f"a-{suffix}@example.com")
        headers_b = register(client, f"b-{suffix}@example.com")
        cases = client.get('/api/investigations', headers=headers_a)
        assert cases.status_code == 200 and cases.json()
        case_id = cases.json()[0]['id']
        log = ("2026-10-18T09:00:00Z Failed password for admin from 203.0.113.9 port 22\n"
               "2026-10-18T09:01:00Z Failed password for admin from 203.0.113.9 port 22\n"
               "2026-10-18T09:02:00Z Failed password for admin from 203.0.113.9 port 22\n").encode()
        uploaded = client.post('/api/evidence/upload', headers=headers_a, data={"investigation_id":case_id}, files={"file":("auth.log",log,"text/plain")})
        assert uploaded.status_code == 201, uploaded.text
        item = uploaded.json(); assert item['event_count'] == 3 and item['finding_count'] == 1
        detail = client.get(f"/api/evidence/{item['id']}", headers=headers_a).json()
        finding = detail['findings'][0]
        assert finding['rule_id'] == 'AUTH-001' and len(finding['event_ids']) == 3
        assert client.get(f"/api/evidence/{item['id']}", headers=headers_b).status_code == 404
        assert client.get(f"/api/evidence/{item['id']}/verify", headers=headers_a).json()['verified'] is True
        from app.config import UPLOAD_DIR
        from app.database import SessionLocal
        from app.models import Evidence
        with SessionLocal() as db:
            stored_name = db.get(Evidence, item['id']).stored_name
        stored_path = UPLOAD_DIR / stored_name
        original_bytes = stored_path.read_bytes()
        stored_path.write_bytes(original_bytes + b'tamper')
        assert client.get(f"/api/evidence/{item['id']}/verify", headers=headers_a).json()['verified'] is False
        stored_path.write_bytes(original_bytes)
        assert client.get(f"/api/evidence/{item['id']}/verify", headers=headers_a).json()['verified'] is True
        duplicate = client.post('/api/evidence/upload', headers=headers_a, data={"investigation_id":case_id}, files={"file":("copy.log",log,"text/plain")})
        assert duplicate.status_code == 409
        for fmt, expected in [('json','application/json'),('pdf','application/pdf')]:
            generated = client.post(f"/api/evidence/{item['id']}/reports/{fmt}", headers=headers_a)
            assert generated.status_code == 200, generated.text
            download = client.get(generated.json()['download_url'], headers=headers_a)
            assert download.status_code == 200 and len(download.content) > 100
            if fmt == 'pdf': assert download.content.startswith(b'%PDF-')
            assert expected in download.headers['content-type']
        for dataset in ['events', 'findings', 'evidence']:
            generated = client.post(f"/api/evidence/{item['id']}/reports/csv?dataset={dataset}", headers=headers_a)
            assert generated.status_code == 200, generated.text
            download = client.get(generated.json()['download_url'], headers=headers_a)
            assert download.status_code == 200 and download.content.startswith(b'\xef\xbb\xbf')
        reports = client.get('/api/reports', headers=headers_a)
        assert reports.status_code == 200 and len(reports.json()) == 5
        history = client.get('/api/history', headers=headers_a).json()
        assert any(row['kind'] == 'Evidence' and item['filename'] in row['target'] for row in history)
        assert any(row['kind'] == 'Report' for row in history)
        audit = client.get('/api/audit', headers=headers_a).json()
        assert any(row['action'] == 'account_created' for row in audit)
        assert client.get(f"/api/reports/{reports.json()[0]['id']}/download", headers=headers_b).status_code == 404


def test_processing_failure_retains_original_and_marks_failed(monkeypatch):
    import app.main as main_module
    with TestClient(app) as client:
        headers = register(client, f"failure-{uuid.uuid4().hex}@example.com")
        cases = client.get('/api/investigations', headers=headers).json()
        def fail_parser(*args, **kwargs):
            raise RuntimeError("synthetic parser failure")
        monkeypatch.setattr(main_module, 'parse_log', fail_parser)
        response = client.post('/api/evidence/upload', headers=headers, data={"investigation_id":cases[0]['id']}, files={"file":("preserve.log",b"synthetic evidence\n","text/plain")})
        assert response.status_code == 500
        evidence = client.get('/api/evidence', headers=headers).json()
        failed = next(row for row in evidence if row['filename'] == 'preserve.log')
        assert failed['status'] == 'failed' and failed['sha256']
        from app.config import UPLOAD_DIR
        import hashlib
        stored = list(UPLOAD_DIR.glob('*.log'))
        assert any(hashlib.sha256(path.read_bytes()).hexdigest() == failed['sha256'] for path in stored)


def test_upload_limit_filename_sanitization_and_invalid_settings():
    with TestClient(app) as client:
        email = f"limits-{uuid.uuid4().hex}@example.com"
        headers = register(client, email)
        settings = {"display_name":"Test User", "max_upload_mb":1, "alert_threshold":3, "display_timezone":"Asia/Kolkata"}
        updated = client.put('/api/settings', headers=headers, json=settings)
        assert updated.status_code == 200 and updated.json()['display_timezone'] == 'Asia/Kolkata'
        invalid = client.put('/api/settings', headers=headers, json={**settings, "alert_threshold":1})
        assert invalid.status_code == 422
        oversized = client.post('/api/evidence/upload', headers=headers, files={"file":("big.log",b"x"*(1024*1024+1),"text/plain")})
        assert oversized.status_code == 413
        valid = client.post('/api/evidence/upload', headers=headers, files={"file":("..\\..\\safe.log",b"2026-10-18T09:00:00Z service started\n","text/plain")})
        assert valid.status_code == 201 and valid.json()['filename'] == 'safe.log'
        failed_login = client.post('/api/auth/login', json={"email":email,"password":"wrong-password"})
        assert failed_login.status_code == 401
        audit = client.get('/api/audit', headers=headers).json()
        assert any(row['action'] == 'login_failed' and row['outcome'] == 'denied' for row in audit)


def test_report_generation_failure_is_recorded(monkeypatch):
    import app.main as main_module
    with TestClient(app) as client:
        headers = register(client, f"report-fail-{uuid.uuid4().hex}@example.com")
        cases = client.get('/api/investigations', headers=headers).json()
        uploaded = client.post('/api/evidence/upload', headers=headers, data={"investigation_id":cases[0]['id']}, files={"file":("valid.log",b"2026-10-18T09:00:00Z service started\n","text/plain")})
        assert uploaded.status_code == 201
        def fail_pdf(_report):
            raise RuntimeError("synthetic PDF renderer failure")
        monkeypatch.setattr(main_module, 'build_pdf', fail_pdf)
        response = client.post(f"/api/evidence/{uploaded.json()['id']}/reports/pdf", headers=headers)
        assert response.status_code == 500
        audit = client.get('/api/audit', headers=headers).json()
        assert any(row['action'] == 'report_generation_failed' and row['outcome'] == 'failed' for row in audit)


def test_event_search_and_consolidated_package():
    import io
    import zipfile
    with TestClient(app) as client:
        headers = register(client, f"search-package-{uuid.uuid4().hex}@example.com")
        case_id = client.get('/api/investigations', headers=headers).json()[0]['id']
        log = ("2026-10-18T09:00:00Z Failed password for admin from 203.0.113.9 port 22\n"
               "2026-10-18T09:01:00Z Failed password for admin from 203.0.113.9 port 22\n"
               "2026-10-18T09:02:00Z Failed password for admin from 203.0.113.9 port 22\n").encode()
        uploaded = client.post('/api/evidence/upload', headers=headers, data={"investigation_id":case_id}, files={"file":("searchable.log",log,"text/plain")})
        assert uploaded.status_code == 201, uploaded.text
        evidence_id = uploaded.json()['id']
        search = client.get('/api/search?q=203.0.113.9', headers=headers)
        assert search.status_code == 200 and search.json()['total'] == 3
        event_id = search.json()['results'][0]['event_id']
        by_id = client.get(f'/api/search?q={event_id}', headers=headers)
        assert by_id.status_code == 200 and any(row['event_id'] == event_id for row in by_id.json()['results'])
        package = client.post(f'/api/evidence/{evidence_id}/export-package', headers=headers)
        assert package.status_code == 200, package.text
        download = client.get(package.json()['download_url'], headers=headers)
        assert download.status_code == 200 and 'application/zip' in download.headers['content-type']
        with zipfile.ZipFile(io.BytesIO(download.content)) as archive:
            names = set(archive.namelist())
            assert {'investigation-report.pdf','investigation.json','events.csv','findings.csv','evidence-inventory.csv','manifest.json'} <= names
            manifest = __import__('json').loads(archive.read('manifest.json'))
            assert manifest['evidence_id'] == evidence_id
        assert client.get(package.json()['download_url'], headers=register(client, f"other-{uuid.uuid4().hex}@example.com")).status_code == 404


def test_original_evidence_download_is_authorized_and_audited():
    with TestClient(app) as client:
        headers = register(client, f"original-download-{uuid.uuid4().hex}@example.com")
        case_id = client.get('/api/investigations', headers=headers).json()[0]['id']
        original = b"2026-10-18T09:00:00Z service started\n"
        uploaded = client.post('/api/evidence/upload', headers=headers, data={"investigation_id":case_id}, files={"file":("original.log",original,"text/plain")})
        assert uploaded.status_code == 201
        evidence_id = uploaded.json()['id']
        response = client.get(f'/api/evidence/{evidence_id}/original-download', headers=headers)
        assert response.status_code == 200 and response.content == original
        other = register(client, f"original-other-{uuid.uuid4().hex}@example.com")
        assert client.get(f'/api/evidence/{evidence_id}/original-download', headers=other).status_code == 404
        audit = client.get('/api/audit', headers=headers).json()
        assert any(row['action'] == 'original_evidence_download' and row['target'] == f'evidence:{evidence_id}' for row in audit)


def test_binary_like_log_is_rejected_with_clear_message_and_retained_record():
    with TestClient(app) as client:
        headers = register(client, f"binary-log-{uuid.uuid4().hex}@example.com")
        case_id = client.get('/api/investigations', headers=headers).json()[0]['id']
        response = client.post('/api/evidence/upload', headers=headers, data={"investigation_id":case_id}, files={"file":("binary.log",b"\x00\x01\x02\x03","text/plain")})
        assert response.status_code == 422
        assert "Binary or unsupported text encoding" in response.json()['detail']
        rows = client.get('/api/evidence', headers=headers).json()
        failed = next(row for row in rows if row['filename'] == 'binary.log')
        assert failed['status'] == 'failed' and failed['sha256']
