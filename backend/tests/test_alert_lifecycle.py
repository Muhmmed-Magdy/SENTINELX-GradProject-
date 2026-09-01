"""Phase 3.3 alert lifecycle and immutable audit trail tests."""
import hashlib


def auth_headers(token):
    return {'Authorization': f'Bearer {token}'}


def change(client, token, alert_id, status, reason):
    return client.patch(
        f'/api/alerts/{alert_id}/status',
        json={'status': status, 'reason': reason},
        headers=auth_headers(token),
    )


def test_lifecycle_transitions_create_immutable_audit_history(auth_client, seed_alert):
    client, token = auth_client
    alert_id = seed_alert()
    assert change(client, token, alert_id, 'acknowledged', 'Initial evidence reviewed.').status_code == 200
    assert change(client, token, alert_id, 'investigating', 'Investigating source IP.').status_code == 200
    assert change(client, token, alert_id, 'resolved', 'Investigation completed.').status_code == 200

    response = client.get(f'/api/alerts/{alert_id}', headers=auth_headers(token))
    history = response.get_json()['status_history']
    assert [(entry['previous_status'], entry['new_status']) for entry in history] == [
        ('new', 'acknowledged'), ('acknowledged', 'investigating'), ('investigating', 'resolved')
    ]
    assert history[0]['changed_by_email'] == 'admin@soc.local'
    assert history[1]['reason'] == 'Investigating source IP.'


def test_invalid_lifecycle_transition_rejected(auth_client, seed_alert):
    client, token = auth_client
    alert_id = seed_alert()
    assert change(client, token, alert_id, 'resolved', 'Skipping investigation.').status_code == 409
    assert change(client, token, alert_id, 'acknowledged', '').status_code == 400
    assert change(client, token, alert_id, 'unknown', 'Invalid state.').status_code == 400


def test_unauthenticated_and_readonly_status_changes_rejected(client, readonly_client, seed_alert):
    alert_id = seed_alert()
    assert client.patch(f'/api/alerts/{alert_id}/status', json={
        'status': 'acknowledged', 'reason': 'Review started.'
    }).status_code == 401
    readonly_client_obj, readonly_token = readonly_client
    assert change(readonly_client_obj, readonly_token, alert_id, 'acknowledged', 'Review started.').status_code == 403


def test_missing_alert_rejected(auth_client):
    client, token = auth_client
    assert change(client, token, 'missing', 'acknowledged', 'Review started.').status_code == 404


def test_audit_rows_cannot_be_updated_or_deleted(auth_client, seed_alert):
    client, token = auth_client
    alert_id = seed_alert()
    assert change(client, token, alert_id, 'acknowledged', 'Review started.').status_code == 200
    import database
    db = database.get_db()
    row = db.execute('SELECT id FROM alert_status_history WHERE alert_id=?', (alert_id,)).fetchone()
    try:
        db.execute('UPDATE alert_status_history SET reason=? WHERE id=?', ('tampered', row['id']))
        db.commit()
        assert False, 'audit history update should be rejected'
    except Exception as error:
        assert 'immutable' in str(error)
    finally:
        db.rollback()
        db.close()
