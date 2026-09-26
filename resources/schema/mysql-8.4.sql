CREATE TABLE auth_remember_me_grants (
    selector_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
    verifier_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    subject_uuid CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    session_uuid CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    generation INT UNSIGNED NOT NULL,
    created_at DATETIME(6) NOT NULL,
    expires_at DATETIME(6) NOT NULL,
    INDEX idx_auth_remember_subject (subject_uuid),
    INDEX idx_auth_remember_session (session_uuid),
    INDEX idx_auth_remember_expiry (expires_at)
) ENGINE=InnoDB;
