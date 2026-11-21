-- optional passphrase protection: the public kdf parameters. the
-- passphrase itself never leaves the sender browser, the working key is
-- derived from the fragment key and the passphrase together.

alter table shares add column has_passphrase integer not null default 0;
alter table shares add column kdf_salt text;
alter table shares add column kdf_iters integer;
