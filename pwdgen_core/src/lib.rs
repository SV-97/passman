use const_format::formatcp;
use num::BigUint;
use pbkdf2::pbkdf2_hmac_array;
use pyrand::{PyMt19937, PySeedable, RandomChoiceIterator};
use secrecy::{ExposeSecret, SecretString};
use sha2::Sha512;
use std::{borrow::Borrow, fmt::Write};

const ASCII_LETTERS: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PassSpec<T, S> {
    pub domain: T,
    pub length: usize,
    pub prohibited_chars: S,
}

impl<T: Borrow<str>, S: Borrow<str>> PassSpec<T, S> {
    pub fn gen_v0(&self, salt: &str, master_pw: &SecretString) -> String {
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
        alphabet.chars().choose(rng2).take(length).collect()
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
            ),
            "7UmX{D?6X-+AaSt-ZN2mw8EqC",
        )
    }
}
