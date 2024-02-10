use argon2::{password_hash::SaltString, Argon2, Params, PasswordHasher, Version};
use const_format::formatcp;
use num::BigUint;
use pbkdf2::pbkdf2_hmac_array;
use pyrand::{PyMt19937, PySeedable, RandomChoiceIterator};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use secrecy::{ExposeSecret, SecretString};
use sha2::Sha512;
use sha3::{Digest, Sha3_512};
use std::{borrow::Borrow, fmt::Write};
use thiserror::Error;

const ASCII_LETTERS: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PassSpec<T, S> {
    pub domain: T,
    pub length: usize,
    pub prohibited_chars: S,
}

#[derive(Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorV1 {
    Argon2(argon2::Error),
    PwdHash(argon2::password_hash::Error),
    MasterPwTooShort,
}

pub type ResultV1<T> = Result<T, ErrorV1>;

impl std::fmt::Display for ErrorV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Argon2(err) => err.fmt(f),
            Self::PwdHash(err) => err.fmt(f),
            Self::MasterPwTooShort => {
                f.write_str("Master password is too short. Has to be at least 8 chars")
            }
        }
    }
}

impl<T: Borrow<str>, S: Borrow<str>> PassSpec<T, S> {
    pub fn gen_v0(&self, salt: &str, master_pw: &SecretString) -> SecretString {
        const BASE_ALPHABET: &str = formatcp!("{ASCII_LETTERS}123456789!,;.-_+-*()[]{{}}$%=?");
        const N_ITERS: usize = 9600;
        let &PassSpec {
            ref domain,
            length,
            ref prohibited_chars,
        } = self;

        let prohibited_chars = format!("{}OIlL", prohibited_chars.borrow());
        let alphabet: String = BASE_ALPHABET
            .chars()
            .filter(|c| !prohibited_chars.contains(*c))
            .collect();
        dbg!(alphabet.len());

        let rng = &mut PyMt19937::py_seed(format!("{salt}/archive")); // PyMt19937::py_seed(alphabet.clone());
        let presalt: String = alphabet.chars().choose(rng).take(50).collect();
        let hash_str = SecretString::new(format!(
            "{presalt}{}{}",
            master_pw.expose_secret(),
            domain.borrow()
        ));

        let salty_salt = (rng
            .randrange_from_zero(&BigUint::from(10_usize).pow(100))
            .unwrap()
            + length)
            .to_str_radix(10);

        let hashed = pbkdf2_hmac_array::<Sha512, 64>(
            hash_str.expose_secret().as_bytes(),
            salty_salt.as_bytes(),
            N_ITERS.try_into().unwrap(),
        );

        // Converts bytes to a hex string similar to python's bytes.hex method
        let hex_byte_str: String = hashed.iter().fold(String::new(), |mut acc, byte| {
            write!(&mut acc, "{:02x}", byte).unwrap();
            acc
        });
        let rng2 = &mut PyMt19937::py_seed(hex_byte_str);
        SecretString::new(alphabet.chars().choose(rng2).take(length).collect())
    }

    // Note that if the provided `password_statisfies_rules` isn't satisfiable this function won't ever return :)
    pub fn gen_v2(
        &self,
        salt: [u8; 16],
        master_pw: &SecretString,
        password_statisfies_rules: impl Fn(&str) -> bool,
    ) -> ResultV1<SecretString> {
        const DIGEST_SIZE: usize = 64;
        let master_pw_len = master_pw.expose_secret().len();
        if master_pw_len < 8 {
            Err(ErrorV1::MasterPwTooShort)
        } else {
            // construct the password that's actually fed into argon2 by combining password, domain
            // and salt through SHA3
            let mut hasher = Sha3_512::new();
            hasher.update(master_pw.expose_secret().as_bytes());
            hasher.update(self.domain.borrow().as_bytes());
            hasher.update(salt);
            let user_hash = <[u8; DIGEST_SIZE]>::from(hasher.finalize());

            // determine alphabet from which password characters will be chosen
            const BASE_ALPHABET: &str = formatcp!("{ASCII_LETTERS}123456789!,;.-_+-*()[]{{}}$%=?");
            let alphabet: String = BASE_ALPHABET
                .chars()
                .filter(|c| !self.prohibited_chars.borrow().contains(*c))
                .collect();

            // set up argon2 instance
            let salt = SaltString::encode_b64(&salt).expect("Internal error: invalid salt");
            // seems to be a reasonable setting with a 25-character password generating in about 0.5-ish seconds
            const T_COST: u32 = 5;
            let kdf = Argon2::new(
                argon2::Algorithm::Argon2id,
                Version::V0x13,
                Params::new(Params::DEFAULT_M_COST, T_COST, 8, Some(DIGEST_SIZE))
                    .map_err(ErrorV1::Argon2)?,
            );

            // allocate some space for the password we generate and for the current "password" that's fed into argon2
            let mut generated_pw = String::with_capacity(self.length);
            // initialize argon2 password with the user-input based hash
            let mut curr_pw: [u8; DIGEST_SIZE] = user_hash;
            loop {
                // we loop and generate passwords. Starting with the user input hash we generate single password
                // characters one by one by iterating argon2, seeding 20-iteration chacha PRNGs with the argon2 output
                // and using the PRNG to select a character from the alphabet.
                // The outer loop loops until a generated password satisfies the user provided "rule" predicate - basically
                // rejection sampling the pw-distribution the user implicitly defines with that ruleset.
                for _ in 0..self.length {
                    let digest = kdf
                        .hash_password(&curr_pw, &salt)
                        .map_err(ErrorV1::PwdHash)?
                        .hash
                        .unwrap();
                    let digest_bytes: [u8; 64] = digest
                        .as_bytes()
                        .try_into()
                        .expect("Something went seriously wrong");
                    let seed = digest_bytes[0..32].try_into().unwrap();
                    let chacha = &mut ChaCha20Rng::from_seed(seed);
                    let index = chacha.gen_range(0..alphabet.len());
                    generated_pw.push(alphabet.chars().nth(index).unwrap());
                    curr_pw.copy_from_slice(&digest_bytes);
                }

                // if the generated password is fine we use it...
                if password_statisfies_rules(&generated_pw) {
                    break Ok(SecretString::new(generated_pw));
                } else {
                    // ...otherwise we start over from scratch.
                    // Note that the last character's argon2 digest of the current password is fed into
                    // the argon2 instance for the next password's first character.
                    generated_pw.clear()
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_gen() {
        let spec = PassSpec {
            domain: "Thomann",
            length: 25,
            prohibited_chars: "",
        };
        assert_eq!(
            spec.gen_v0(
                "just_another_salt",
                &SecretString::new("Passwort".to_string())
            )
            .expose_secret(),
            "7UmX{D?6X-+AaSt-ZN2mw8EqC",
        )
    }

    #[test]
    fn v2_testy_boi() {
        let spec = PassSpec {
            domain: "Thomann",
            length: 25,
            prohibited_chars: "OIlL",
        };
        let salt = [
            82, 67, 79, 175, 96, 126, 77, 82, 158, 82, 6, 10, 183, 123, 18, 236,
        ];
        assert_eq!(
            spec.gen_v2(salt, &SecretString::new("Passwort".to_string()), |pw| pw
                .chars()
                .nth(0)
                .unwrap()
                .is_uppercase())
                .map(|s| s.expose_secret().clone()),
            Ok("V66(3X9)B_{%9S;4K$yGWtvhy".to_owned()),
        )
    }
}
