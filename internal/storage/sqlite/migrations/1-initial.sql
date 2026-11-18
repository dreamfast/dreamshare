-- Server generated tokens, opaque ciphertext and telemetry only.
-- Nothing in this file names content.
-- Child rows die with their parent. The foreign keys are the retention model.

create table shares(id text primary key,             -- 128-bit base62 capability token
       format_version text not null,    -- pins frame format and kdf, 'ds1' for now
       title_ct blob, manifest_ct blob, check_ct blob,   -- client ciphertext, unreadable here
       file_count integer not null default 0,
       total_bytes bigint not null default 0,
       expiry_mode text not null check (expiry_mode in ('burn_on_ack','ttl')),
       expires_at integer not null,     -- always set, so an unclaimed link still dies
       acked_at integer,                -- first verified decrypt, the wipe trigger
       terminal_at integer,             -- when the share reached a terminal state, the tombstone clock
       max_attempts integer not null default 5 check (max_attempts >= 1),
                                         -- a zero cap makes every file permanently unfetchable
       max_downloads integer check (max_downloads is null or max_downloads >= 1),
                                         -- share wide byte-0 cap, null means unlimited
       downloads_used integer not null default 0,
       manager_token_hash text,         -- hashed at rest so a db leak grants no revoke rights
       turnstile_ok integer not null default 0,
       created_ip text,                 -- full or truncated per IP_MODE
       created_country text, created_asn text,
       created_ua text,                 -- raw, parsed to families at read time
       created_at integer,              -- unix epoch utc everywhere
       status text not null default 'pending'
         check (status in ('pending','active','delivered','wiped','expired','revoked')));

create table share_files(id text primary key,
            share_id text not null references shares(id) on delete cascade,
            position integer not null,
            object_key text not null,            -- server generated, never from a filename
            byte_size bigint not null,           -- ciphertext bytes
            sha256 blob,                         -- hash of the ciphertext object.
                                                  -- The plaintext fingerprint rides in the manifest.
            attempts integer not null default 0, -- per file byte-0 fetch counter
            frame_count integer not null,
            frame_size integer not null,         -- plaintext bytes per frame, 1 MiB in ds1
            part_size integer not null,
            b2_upload_id text, b2_etag text,
            b2_file_id text,                     -- needed to delete a specific b2 version
            acked_at integer);                   -- per file ack, the share flips when all files ack

create table upload_sessions(id text primary key,
                share_id text not null references shares(id) on delete cascade,
                file_id text not null,           -- one session per file, text only shares have none
                part_size integer not null,
                expected_parts integer not null,
                b2_upload_id text,               -- the storage side multipart upload id
                bytes_received bigint not null default 0,
                chunk_secret blob,               -- hmac secret for look ahead part tokens
                created_at integer not null,
                expires_at integer not null,
                completed_at integer,
                client_ip_hash text);

create table upload_parts(sid text not null references upload_sessions(id) on delete cascade,
             part_number integer not null,
             etag text, size integer not null, sha256 blob,
             primary key (sid, part_number));

create table share_events(id integer primary key autoincrement,
             share_id text not null references shares(id) on delete cascade,
             ts integer not null,
             event text not null check (event in
               ('created','finalised','check_ok','check_fail','downloaded','ack','notified',
                'wiped','revoked','expired')),
             ip text, country text, ua text,
             bytes integer, ip_hash text);

-- Staff side. One admin user, no registration, no invites.
create table admin_users(id text primary key,
            email text not null unique,          -- normalised in Go before it lands here
            display_name text,
            password_hash text not null,         -- argon2id, the only password in the system
            totp_secret_ct blob,                 -- sealed under an env secret, 2fa on by default
            status text not null default 'active' check (status in ('active','disabled')),
            created_at integer not null,
            last_login_at integer,
            failed_attempts integer not null default 0,
            locked_until integer);

create table admin_sessions(token_hash text primary key,
               user_id text not null references admin_users(id) on delete cascade,
               created_at integer not null,
               last_seen_at integer not null,
               expires_at integer not null,
               ip_hash text, user_agent_hash text);

-- one owner account, the promise is case blind uniqueness
create unique index idx_admin_users_email_ci on admin_users(lower(email));

create table admin_ip_blocks(ip_cidr text primary key,
                reason text, created_by text, created_at integer not null,
                expires_at integer);

-- Notification retry net. At most one unsent row per share and kind.
-- Retries update, they never insert.
-- The notify rate bound keys on created_at, not sent_at, so a mail outage
-- cannot void the limit.
create table outbox(id integer primary key autoincrement,
       share_id text not null references shares(id) on delete cascade,
       to_addr text,                      -- nullable so the address can be blanked after send
       kind text not null check (kind in ('downloaded')),
       created_at integer not null,
       sent_at integer,
       attempts integer not null default 0,
       last_error text);

-- No rollup table. Live sums are cheap at this scale and avoid a second
-- retention story.

-- plain index: two shares can be created in the same second, uniqueness here
-- would refuse the second one outright
create index idx_shares_created_at on shares(created_at);
-- the schema owns the one unsent row per share and kind rule, so a racy
-- second insert fails instead of trusting the caller
create unique index idx_outbox_one_unsent on outbox(share_id, kind) where sent_at is null;
-- manager link lookups are by hash, duplicates must be impossible
create unique index idx_shares_manager_token on shares(manager_token_hash) where manager_token_hash is not null;
create index idx_share_files_share on share_files(share_id);
create index idx_upload_sessions_share on upload_sessions(share_id);
create index idx_share_events_share_ts on share_events(share_id, ts);
create index idx_outbox_unsent on outbox(sent_at) where sent_at is null;
create index idx_shares_status_expiry on shares(status, expires_at);
create index idx_shares_terminal on shares(terminal_at) where terminal_at is not null;
