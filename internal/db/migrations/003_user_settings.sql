CREATE TABLE IF NOT EXISTS user_settings (
    user_id UUID PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    github_token_ciphertext BYTEA,
    openai_api_key_ciphertext BYTEA,
    openai_base_url TEXT NOT NULL DEFAULT '',
    openai_model TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
