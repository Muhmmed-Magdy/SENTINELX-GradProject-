"""Phase 3.1 detection rule management API tests."""


def test_detection_rules_require_auth(client):
    response = client.get('/api/detection-rules')
    assert response.status_code == 401


def test_admin_can_list_rules_with_runtime_metadata(auth_client, seed_alert):
    client, token = auth_client
    alert_id = seed_alert(rule_name='BRUTE_FORCE_LOGIN')
    response = client.get('/api/detection-rules', headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 200
    rules = response.get_json()
    brute_force = next(rule for rule in rules if rule['name'] == 'BRUTE_FORCE_LOGIN')
    assert brute_force['enabled'] is True
    assert brute_force['threshold'] == 3
    assert brute_force['time_window_seconds'] == 300
    assert brute_force['trigger_count'] == 1
    assert brute_force['last_triggered'] is not None
    assert alert_id


def test_admin_can_update_supported_rule_settings(auth_client):
    client, token = auth_client
    headers = {'Authorization': f'Bearer {token}'}
    response = client.patch(
        '/api/detection-rules/BRUTE_FORCE_LOGIN',
        json={'enabled': False, 'threshold': 5, 'time_window_seconds': 600},
        headers=headers,
    )
    assert response.status_code == 200
    rules = client.get('/api/detection-rules', headers=headers).get_json()
    rule = next(rule for rule in rules if rule['name'] == 'BRUTE_FORCE_LOGIN')
    assert rule['enabled'] is False
    assert rule['threshold'] == 5
    assert rule['time_window_seconds'] == 600


def test_disabled_rule_is_not_evaluated(client, auth_client, ingest_headers):
    admin_client, token = auth_client
    headers = {'Authorization': f'Bearer {token}'}
    response = admin_client.patch(
        '/api/detection-rules/PRIVILEGE_ESCALATION',
        json={'enabled': False},
        headers=headers,
    )
    assert response.status_code == 200
    response = client.post(
        '/api/logs/ingest',
        json={'logs': [{'event_id': '4728', 'message': 'user added to administrators group'}]},
        headers=ingest_headers,
    )
    assert response.status_code == 200
    assert response.get_json()['alerts_generated'] == 0


def test_non_admin_cannot_update_rules(analyst_client):
    client, token = analyst_client
    response = client.patch(
        '/api/detection-rules/BRUTE_FORCE_LOGIN',
        json={'enabled': False},
        headers={'Authorization': f'Bearer {token}'},
    )
    assert response.status_code == 403


def test_rule_update_validation(auth_client):
    client, token = auth_client
    headers = {'Authorization': f'Bearer {token}'}
    assert client.patch(
        '/api/detection-rules/UNKNOWN', json={'enabled': False}, headers=headers
    ).status_code == 404
    assert client.patch(
        '/api/detection-rules/BRUTE_FORCE_LOGIN', json={'enabled': 'false'}, headers=headers
    ).status_code == 400
    assert client.patch(
        '/api/detection-rules/PRIVILEGE_ESCALATION',
        json={'threshold': 5},
        headers=headers,
    ).status_code == 400
    assert client.patch(
        '/api/detection-rules/BRUTE_FORCE_LOGIN', json={'unexpected': True}, headers=headers
    ).status_code == 400
    assert client.patch(
        '/api/detection-rules/BRUTE_FORCE_LOGIN', data='not-json', headers=headers,
        content_type='application/json',
    ).status_code == 400
