// DATABASE_URL="sqlite://passman.db" cargo sqlx prepare
use colored::Colorize;
use eyre::{eyre, Report, Result};
use inquire::{
    ui::{self, Attributes, RenderConfig, StyleSheet, Styled},
    CustomType, InquireError,
};
use lazy_static::lazy_static;
use pwdgen_core::{PassSpec, V0_DEFAULT_ALPHABET, V2_DEFAULT_ALPHABET};
use rand::Rng;
use secrecy::{ExposeSecret, SecretString};
use sqlx::{
    migrate::{Migrate, Migrator},
    sqlite::SqliteConnectOptions,
    ConnectOptions, SqliteConnection,
};

use std::{collections::HashSet, fmt, str::FromStr, time::Duration};

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");
const DATABASE_URL: &str = "sqlite://passman.db";
lazy_static! {
    static ref DEFAULT_RENDER_CONFIG: RenderConfig = {
        let mut conf = RenderConfig::default_colored()
            .with_highlighted_option_prefix(Styled::new("> ").with_fg(ui::Color::LightCyan))
            .with_default_value(
                StyleSheet::new()
                    .with_fg(ui::Color::DarkCyan)
                    .with_attr(Attributes::ITALIC),
            );
        conf.prompt = StyleSheet::default().with_attr(Attributes::BOLD);
        conf
    };
}

fn new_styled_select<T: fmt::Display>(message: &str, options: Vec<T>) -> inquire::Select<T> {
    inquire::Select::new(message, options).with_render_config(*DEFAULT_RENDER_CONFIG)
}

fn new_styled_confirm(message: &str) -> inquire::Confirm {
    inquire::Confirm::new(message).with_render_config(*DEFAULT_RENDER_CONFIG)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum PwVersion {
    Zero,
    Two,
}

impl TryFrom<String> for PwVersion {
    type Error = Report;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.as_str() {
            "0" => Ok(Self::Zero),
            "v2" => Ok(Self::Two),
            v => Err(eyre!("Unknown version: {}", v)),
        }
    }
}

impl fmt::Display for PwVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            PwVersion::Zero => "0",
            PwVersion::Two => "v2",
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Restrictions {
    min_count_digit: u32,
    min_count_lower: u32,
    min_count_upper: u32,
    min_count_symbol: u32,
}

impl Restrictions {
    /// Returns true if str is valid w.r.t restrictions; false otherwise
    pub fn validate_str(self, pw: &str) -> bool {
        pw.chars().filter(|c| c.is_ascii_digit()).count() >= self.min_count_digit as usize
            && pw.chars().filter(|c| c.is_lowercase()).count() >= self.min_count_lower as usize
            && pw.chars().filter(|c| c.is_uppercase()).count() >= self.min_count_upper as usize
            && pw.chars().filter(|c| !c.is_alphanumeric()).count() >= self.min_count_symbol as usize
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DbPassSpec {
    uid: i64,
    domain: String,
    length: usize,
    prohibited_chars: String,
    version: PwVersion,
    restrictions: Restrictions,
}

impl fmt::Display for DbPassSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.domain)
    }
}

async fn retrieve_current_list(conn: &mut SqliteConnection) -> Result<Vec<DbPassSpec>> {
    sqlx::query!("SELECT * from domains")
        .fetch_all(conn)
        .await?
        .into_iter()
        .map(|record| {
            Ok(DbPassSpec {
                uid: record.uid,
                domain: record.name,
                length: usize::try_from(record.length)?,
                prohibited_chars: record.prohibited_characters,
                version: record.version.try_into()?,
                restrictions: Restrictions {
                    min_count_lower: u32::try_from(record.min_count_lowercase)?,
                    min_count_upper: u32::try_from(record.min_count_uppercase)?,
                    min_count_digit: u32::try_from(record.min_count_digit)?,
                    min_count_symbol: u32::try_from(record.min_count_symbol)?,
                },
            })
        })
        .collect::<Result<Vec<_>>>()
}

fn prompt_version_select() -> inquire::Select<'static, PwVersion> {
    new_styled_select(
        "Which password derivation version do you want to use? (version 2 is recommended)",
        vec![PwVersion::Two, PwVersion::Zero],
    )
}

fn prompt_pw_length() -> CustomType<'static, u32> {
    inquire::CustomType::new("How long do you want the password to be?")
        .with_default(25)
        .with_help_message("Enter an integer value. Please use a value no smaller than 12.")
}

fn prompt_restrictions(default: Option<Restrictions>) -> Result<Restrictions, InquireError> {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum BasicRes {
        Lower,
        Upper,
        Digit,
        Symbol,
    }
    impl fmt::Display for BasicRes {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(match self {
                BasicRes::Lower => "At least one lowercase letter",
                BasicRes::Upper => "At least one uppercase letter",
                BasicRes::Digit => "At least one digit",
                BasicRes::Symbol => "At least one non-alphanumeric symbol",
            })
        }
    }
    let default = default
        .map(|res| {
            let mut v = vec![];
            if res.min_count_lower == 1 {
                v.push(0)
            }
            if res.min_count_upper == 1 {
                v.push(1)
            }
            if res.min_count_digit == 1 {
                v.push(2)
            }
            if res.min_count_symbol == 1 {
                v.push(3)
            }
            v
        })
        .unwrap_or_default();
    let selected_res = inquire::MultiSelect::new(
        "Please select applicable restrictions",
        vec![
            BasicRes::Lower,
            BasicRes::Upper,
            BasicRes::Digit,
            BasicRes::Symbol,
        ],
    )
    .with_default(&default)
    .with_render_config(*DEFAULT_RENDER_CONFIG)
    .prompt()?;

    Ok(Restrictions {
        min_count_digit: selected_res.contains(&BasicRes::Digit) as u32,
        min_count_lower: selected_res.contains(&BasicRes::Lower) as u32,
        min_count_symbol: selected_res.contains(&BasicRes::Symbol) as u32,
        min_count_upper: selected_res.contains(&BasicRes::Upper) as u32,
    })
}

macro_rules! unwrap_ret {
    ($option:expr) => {
        match $option {
            Some(val) => val,
            None => return Ok(()),
        }
    };
    ($option:expr, $return_expr:expr) => {
        match $option {
            Some(val) => val,
            None => return $return_expr,
        }
    };
}

async fn insert_new(conn: &mut SqliteConnection) -> Result<()> {
    let domain = unwrap_ret!(
        inquire::Text::new("What's the name of the domain you want to add?").prompt_skippable()?
    );
    // check if the domain is already in the DB and if so report an error
    let res = sqlx::query!(
        "
            SELECT COUNT(*) > 0 AS name_exists
            FROM domains
            WHERE name = ?;
        ",
        domain,
    )
    .fetch_one(&mut *conn)
    .await?;
    if res.name_exists != 0 {
        println!(
            "{}",
            "This name is already taken. Please choose another one.".magenta()
        );
        return Ok(());
    }

    let length = unwrap_ret!(prompt_pw_length().prompt_skippable()?);
    let version = unwrap_ret!(prompt_version_select().prompt_skippable()?);
    let prohibited_chars = unwrap_ret!(inquire::Text::new(
        "What characters (if any) should **not** be part of the password?"
    )
    .with_default(match version {
        PwVersion::Two => "OIlL",
        PwVersion::Zero => "",
    })
    .prompt_skippable()?);
    let restrictions = prompt_restrictions(None)?;
    let version_str = version.to_string();
    sqlx::query!(
        "
        INSERT INTO domains (name, length, prohibited_characters, version, min_count_lowercase, min_count_uppercase, min_count_digit, min_count_symbol)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?);
        ",
        domain,
        length,
        prohibited_chars,
        version_str,
        restrictions.min_count_lower,
        restrictions.min_count_upper,
        restrictions.min_count_digit,
        restrictions.min_count_symbol,
    )
    .execute(conn)
    .await?;
    println!("Successfully added {}.", domain);
    Ok(())
}

async fn query(conn: &mut SqliteConnection) -> Result<()> {
    enum QueryChoice {
        GetPass,
        Update,
        Delete,
    }
    impl fmt::Display for QueryChoice {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(match self {
                Self::GetPass => "Get password for domain",
                Self::Update => "Update settings for domain",
                Self::Delete => "Delete entry from database",
            })
        }
    }

    let current = retrieve_current_list(conn).await?;
    if current.is_empty() {
        println!("There are no stored domains yet. You can only start querying once you inserted at least one.");
    } else {
        let selected_domain =
            unwrap_ret!(new_styled_select("Select domain:", current).prompt_skippable()?);

        let choices = vec![
            QueryChoice::GetPass,
            QueryChoice::Update,
            QueryChoice::Delete,
        ];
        let query_action =
            unwrap_ret!(new_styled_select("What do you want to do?", choices).prompt_skippable()?);
        match query_action {
            QueryChoice::GetPass => {
                let pass = get_pass(selected_domain)?;
                println!(
                    "Generated password (printed white on white): >>{}<<",
                    pass.expose_secret().white().on_white()
                );
            }
            QueryChoice::Delete => deletion_dialog(conn, selected_domain).await?,
            QueryChoice::Update => update_entry(conn, selected_domain).await?,
        }
    }
    Ok(())
}

fn apply_prohibited_chars(alphabet: &str, prohibited_chars: &str) -> String {
    alphabet
        .chars()
        .filter(|c| !prohibited_chars.contains(*c))
        .collect()
}

fn get_pass(spec: DbPassSpec) -> Result<SecretString> {
    let master_pw = SecretString::new(
        inquire::Password::new("Master password:")
            .with_display_mode(inquire::PasswordDisplayMode::Hidden)
            .prompt()?,
    );
    match spec.version {
        PwVersion::Zero => {
            let spec = PassSpec {
                domain: spec.domain,
                length: spec.length,
                alphabet: apply_prohibited_chars(V0_DEFAULT_ALPHABET, &spec.prohibited_chars),
            };
            Ok(spec.gen_v0("just_another_salt", &master_pw))
        }
        PwVersion::Two => {
            let base_spec = PassSpec {
                domain: spec.domain,
                length: spec.length,
                alphabet: apply_prohibited_chars(V2_DEFAULT_ALPHABET, &spec.prohibited_chars),
            };
            const SALT: [u8; 16] = [
                82, 67, 79, 175, 96, 126, 77, 82, 158, 82, 6, 10, 183, 123, 18, 236,
            ];
            Ok(base_spec.gen_v2(SALT, &master_pw, |pw| spec.restrictions.validate_str(pw))?)
        }
    }
}

async fn update_entry(conn: &mut SqliteConnection, spec: DbPassSpec) -> Result<()> {
    enum UpdateChoice {
        ModifyProhibitedChars,
        UpdatePwVersion,
        Length,
        Restrictions,
    }
    impl fmt::Display for UpdateChoice {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(match self {
                Self::ModifyProhibitedChars => "Modify prohibited chars",
                Self::UpdatePwVersion => "Modify password derivation version",
                Self::Length => "Modify password length",
                Self::Restrictions => "Modify password restrictions",
            })
        }
    }

    let choices = vec![
        UpdateChoice::ModifyProhibitedChars,
        UpdateChoice::UpdatePwVersion,
        UpdateChoice::Length,
        UpdateChoice::Restrictions,
    ];
    let query_action = new_styled_select("What do you want to do?", choices).prompt();
    match query_action? {
        UpdateChoice::ModifyProhibitedChars => {
            let new = unwrap_ret!(inquire::Text::new("New prohibited characters: ")
                .with_initial_value(&spec.prohibited_chars)
                .prompt_skippable()?);
            sqlx::query!(
                "
                UPDATE domains
                SET prohibited_characters = ?
                WHERE uid = ?;
                ",
                new,
                spec.uid,
            )
            .execute(conn)
            .await?;
            println!("Successfully updated prohibited characters.");
        }
        UpdateChoice::UpdatePwVersion => {
            // yes this is very fragile and leaks details from prompt_version_select, but idc.
            let new = unwrap_ret!(prompt_version_select()
                .with_starting_cursor(match spec.version {
                    PwVersion::Two => 0,
                    PwVersion::Zero => 1,
                })
                .prompt_skippable()?)
            .to_string();
            sqlx::query!(
                "
                UPDATE domains
                SET version = ?
                WHERE uid = ?;
                ",
                new,
                spec.uid,
            )
            .execute(conn)
            .await?;
            println!("Successfully updated password derivation version.");
        }
        UpdateChoice::Length => {
            let new = unwrap_ret!(prompt_pw_length().prompt_skippable()?);
            sqlx::query!(
                "
                UPDATE domains
                SET length = ?
                WHERE uid = ?;
                ",
                new,
                spec.uid,
            )
            .execute(conn)
            .await?;
            println!("Successfully updated password length.");
        }
        UpdateChoice::Restrictions => {
            let new = prompt_restrictions(Some(spec.restrictions))?;
            sqlx::query!(
                "
                UPDATE domains
                SET min_count_lowercase = ?,
                    min_count_uppercase = ?,
                    min_count_digit = ?,
                    min_count_symbol = ?
                WHERE uid = ?;
                ",
                new.min_count_lower,
                new.min_count_upper,
                new.min_count_digit,
                new.min_count_symbol,
                spec.uid,
            )
            .execute(conn)
            .await?;
            println!("Successfully updated password length.");
        }
    }
    Ok(())
}

async fn deletion_dialog(conn: &mut SqliteConnection, spec: DbPassSpec) -> Result<()> {
    let confirmed_delete = new_styled_confirm(&format!(
        "Do you really want to remove the entry for domain '{}'?",
        spec.domain
    ))
    .with_render_config(*DEFAULT_RENDER_CONFIG)
    .with_default(false)
    .prompt_skippable()?
    .unwrap_or(false);
    if confirmed_delete {
        let config = DEFAULT_RENDER_CONFIG
            .with_help_message(ui::StyleSheet::default().with_fg(ui::Color::LightRed))
            .with_text_input(ui::StyleSheet::default().with_fg(ui::Color::LightRed));
        let name = inquire::Text::new("Please type the name of the domain to verify its deletion")
            .with_help_message("The stored data will be irretrievably lost!")
            .with_render_config(config)
            .prompt()?;
        if name == spec.domain {
            sqlx::query!("DELETE FROM domains WHERE uid = ?;", spec.uid)
                .execute(conn)
                .await?;
            return Ok(());
        }
    }
    println!("Not deleting domain");
    Ok(())
}

async fn prepare_db() -> Result<SqliteConnection> {
    let mut conn = SqliteConnectOptions::from_str(DATABASE_URL)?
        .create_if_missing(true)
        .optimize_on_close(true, None)
        .connect()
        .await?;

    conn.ensure_migrations_table().await?;
    // find out which migrations have already been applied and apply
    // all those that haven't been applied yet
    let applied_migrations = conn
        .list_applied_migrations()
        .await?
        .into_iter()
        .map(|m| m.checksum)
        .collect::<HashSet<_>>();
    for migration in MIGRATOR
        .migrations
        .iter()
        .skip_while(|m| applied_migrations.contains(&m.checksum))
    {
        conn.apply(migration).await?;
    }
    Ok(conn)
}

#[tokio::main]
async fn main() -> Result<()> {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    enum MainMenuChoice {
        Query,
        CreateNew,
        Exit,
        DropDb,
    }
    impl fmt::Display for MainMenuChoice {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(match self {
                Self::Query => "Query entries",
                Self::CreateNew => "Create a new entry",
                Self::DropDb => "Drop database",
                Self::Exit => "Exit",
            })
        }
    }

    // let mut conn = SqliteConnection::connect("sqlite://totally_not_my_passwords.db").await?;
    let mut conn = prepare_db().await?;

    let main_menu_options = vec![
        MainMenuChoice::Query,
        MainMenuChoice::CreateNew,
        MainMenuChoice::DropDb,
        MainMenuChoice::Exit,
    ];
    let main_select = new_styled_select("Select submenu:", main_menu_options.clone());
    loop {
        let ans = main_select.clone().prompt();
        match ans {
            Ok(MainMenuChoice::Exit) => break,
            Ok(MainMenuChoice::Query) => query(&mut conn).await?,
            Ok(MainMenuChoice::CreateNew) => insert_new(&mut conn).await?,
            Ok(MainMenuChoice::DropDb) => {
                let confirmed_drop =
                    new_styled_confirm("Do you really want to drop (delete) the full database?")
                        .with_render_config(*DEFAULT_RENDER_CONFIG)
                        .with_default(false)
                        .prompt_skippable()?
                        .unwrap_or(false);
                if confirmed_drop {
                    let mut rng = rand::thread_rng();
                    let s: [u8; 2] = rng.gen();
                    let answer: Option<u16> = inquire::CustomType::new(
                &format!("To confirm that you *REALLY* want to delete the complete database please compute {} + {} =",
                            s[0],
                            s[1]
                        )
                    )
                    .with_placeholder("...")
                    .prompt_skippable()?;
                    let correct_answer = (s[0] as u16).checked_add(s[1] as u16).ok_or(eyre!(
                        "Internal error; this should not have happened. Please try again"
                    ))?;
                    if let Some(a) = answer {
                        if a == correct_answer {
                            use sqlx::migrate::MigrateDatabase;
                            let current = retrieve_current_list(&mut conn).await?;
                            println!("Correct. Dropping DB in 5s...");
                            tokio::time::sleep(Duration::from_secs(5)).await;
                            sqlx::Sqlite::drop_database(DATABASE_URL).await?;
                            println!("Dropped database. Printing final contents... ");
                            println!("{:?}", current);
                            return Ok(());
                        } else {
                            println!("Your answer is wrong. Not dropping database.")
                        }
                    } else {
                        println!("Not dropping database.")
                    }
                }
            }
            Err(InquireError::OperationCanceled) => return Ok(()),
            Err(e) => {
                println!("{}", e);
                return Err(eyre!(e));
            }
        }
        println!();
    }
    Ok(())
}
