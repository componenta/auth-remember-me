CREATE TABLE auth_remember_me_grants (
    selector_hash CHAR(64) PRIMARY KEY,
    verifier_hash CHAR(64) NOT NULL,
    subject_uuid UUID NOT NULL,
    session_uuid UUID NOT NULL,
    generation INTEGER NOT NULL CHECK (generation > 0),
    created_at TIMESTAMP(6) WITHOUT TIME ZONE NOT NULL,
    expires_at TIMESTAMP(6) WITHOUT TIME ZONE NOT NULL
);

CREATE INDEX idx_auth_remember_subject
    ON auth_remember_me_grants(subject_uuid);
CREATE INDEX idx_auth_remember_session
    ON auth_remember_me_grants(session_uuid);
CREATE INDEX idx_auth_remember_expiry
    ON auth_remember_me_grants(expires_at);
