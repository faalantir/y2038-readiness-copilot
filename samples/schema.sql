CREATE TABLE device_events (
    id BIGSERIAL PRIMARY KEY,
    device_id TEXT NOT NULL,
    event_time INT NOT NULL,
    created_at INTEGER,
    expires_at INT,
    payload JSONB
);
