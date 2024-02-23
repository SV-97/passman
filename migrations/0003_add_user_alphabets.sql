-- optional user alphabet
ALTER TABLE domains
ADD COLUMN alphabet TEXT DEFAULT NULL;
