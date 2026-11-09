from fastapi.testclient import TestClient
from sentinel.api.app import create_app


def test_api_flow_with_human_approval(container):
    client = TestClient(create_app(container))
    with client.websocket_connect("/ws") as ws:
        assert client.post("/api/simulate/phishing").json()["pending"] >= 2
        assert ws.receive_json()["topic"] in {"incidents", "actions"}
    pending = client.get("/api/approvals").json()
    done = client.post(f"/api/actions/{pending[0]['id']}/approve", json={"analyst": "maheswari"}).json()
    assert done["decision"] == "executed" and done["decided_by"] == "maheswari"
    assert client.post(f"/api/actions/{pending[0]['id']}/approve").status_code == 409
    assert client.get("/api/audit/verify").json()["valid"] is True
    assert client.get("/").status_code == 200
