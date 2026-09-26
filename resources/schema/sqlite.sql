CREATE TABLE auth_remember_me_grants (
    selector_hash TEXT PRIMARY KEY,
    verifier_hash TEXT NOT NULL,
    subject_uuid TEXT NOT NULL,
    session_uuid TEXT NOT NULL,
    generation INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE INDEX auth_remember_me_subject
    ON auth_remember_me_grants(subject_uuid);
CREATE INDEX auth_remember_me_session
    ON auth_remember_me_grants(session_uuid);
CREATE INDEX auth_remember_me_expiry
    ON auth_remember_me_grants(expires_at);
