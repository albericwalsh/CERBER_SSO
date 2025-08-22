# test_auth.py
import pytest

@pytest.mark.asyncio
async def test_register_login_refresh(client):
    response = await client.post("/api/v1/sso/register", json={
        "username": "alice",
        "email": "alice@example.com",
        "password": "SuperSecret123"
    })
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
