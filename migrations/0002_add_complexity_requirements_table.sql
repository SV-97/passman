-- Add new columns with default values

-- minimum number of lowercase characters in password
ALTER TABLE domains
ADD COLUMN min_count_lowercase INTEGER NOT NULL DEFAULT 0;
-- minimum number of uppercase characters in password
ALTER TABLE domains
ADD COLUMN min_count_uppercase INTEGER NOT NULL DEFAULT 0;
-- minimum number of digits in password
ALTER TABLE domains
ADD COLUMN min_count_digit INTEGER NOT NULL DEFAULT 0;
-- minimum number of non-alphanumeric symbols in password
ALTER TABLE domains
ADD COLUMN min_count_symbol INTEGER NOT NULL DEFAULT 0;
