-- the notify address moves server side, the sender hands it over at
-- create and it leaves with the share. check_sha256 binds the ack proof
-- to the sealed check verifier so only a key holder can wipe a share.

alter table shares add column notify_email text;
alter table shares add column check_sha256 text;
