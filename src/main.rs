// DATABASE_URL="" cargo sqlx prepare
use colored::Colorize;
use eyre::{eyre, Report, Result};
use inquire::ui;
use inquire::{self, InquireError};
use pwdgen_core::PassSpec;
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

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct DbPassSpec {
    uid: i64,
    domain: String,
    length: usize,
    prohibited_chars: String,
    version: PwVersion,
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
                length: usize::try_from(record.length).map_err(|e| eyre!(e))?,
                prohibited_chars: record.prohibited_characters,
                version: record.version.try_into()?,
            })
        })
        .collect::<Result<Vec<_>>>()
}

fn prompt_version_select() -> Result<PwVersion, InquireError> {
    inquire::Select::new(
        "Which password derivation version do you want to use? (version 2 is recommended)",
        vec![PwVersion::Two, PwVersion::Zero],
    )
    .prompt()
}

fn prompt_pw_length() -> Result<u32, InquireError> {
    inquire::CustomType::new("How long do you want the password to be?")
        .with_default(25)
        .with_help_message("Enter an integer value. Please use a value no smaller than 12.")
        .prompt()
}

async fn insert_new(conn: &mut SqliteConnection) -> Result<()> {
    let domain = inquire::Text::new("What's the name of the domain you want to add?").prompt()?;
    let length = prompt_pw_length()?;
    let version = prompt_version_select()?;
    let prohibited_chars =
        inquire::Text::new("What characters (if any) should **not** be part of the password?")
            .with_default(match version {
                PwVersion::Two => "OIlL",
                PwVersion::Zero => "",
            })
            .prompt()?;
    let version_str = version.to_string();
    sqlx::query!(
        "
        INSERT INTO domains (name, length, prohibited_characters, version)
        VALUES (?, ?, ?, ?);
        ",
        domain,
        length,
        prohibited_chars,
        version_str,
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
        let selected_domain = inquire::Select::new("Select domain:", current).prompt()?;

        let choices = vec![
            QueryChoice::GetPass,
            QueryChoice::Update,
            QueryChoice::Delete,
        ];
        let query_action = inquire::Select::new("What do you want to do?", choices).prompt();
        match query_action? {
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
                prohibited_chars: spec.prohibited_chars,
            };
            Ok(spec.gen_v0("just_another_salt", &master_pw))
        }
        PwVersion::Two => {
            let spec = PassSpec {
                domain: spec.domain,
                length: spec.length,
                prohibited_chars: spec.prohibited_chars,
            };
            const SALT: [u8; 16] = [
                82, 67, 79, 175, 96, 126, 77, 82, 158, 82, 6, 10, 183, 123, 18, 236,
            ];
            Ok(spec.gen_v2(SALT, &master_pw, |_| true)?)
        }
    }
}

async fn update_entry(conn: &mut SqliteConnection, spec: DbPassSpec) -> Result<()> {
    enum UpdateChoice {
        ModifyProhibitedChars,
        UpdatePwVersion,
        Length,
    }
    impl fmt::Display for UpdateChoice {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(match self {
                Self::ModifyProhibitedChars => "Modify prohibited chars",
                Self::UpdatePwVersion => "Modify password derivation version",
                Self::Length => "Modify password length",
            })
        }
    }

    let choices = vec![
        UpdateChoice::ModifyProhibitedChars,
        UpdateChoice::UpdatePwVersion,
        UpdateChoice::Length,
    ];
    let query_action = inquire::Select::new("What do you want to do?", choices).prompt();
    match query_action? {
        UpdateChoice::ModifyProhibitedChars => {
            let new = inquire::Text::new("New prohibited characters: ")
                .with_initial_value(&spec.prohibited_chars)
                .prompt()?;
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
            let new = prompt_version_select()?.to_string();
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
            let new = prompt_pw_length()?;
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
    }
    Ok(())
}

async fn deletion_dialog(conn: &mut SqliteConnection, spec: DbPassSpec) -> Result<()> {
    let confirmed_delete = inquire::Confirm::new(&format!(
        "Do you really want to remove the entry for domain '{}'?",
        spec.domain
    ))
    .with_default(false)
    .prompt()?;
    if confirmed_delete {
        let config = ui::RenderConfig::default()
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
    let main_select = inquire::Select::new("Select submenu:", main_menu_options.clone());
    loop {
        let ans = main_select.clone().prompt();
        match ans {
            Ok(MainMenuChoice::Exit) => break,
            Ok(MainMenuChoice::Query) => query(&mut conn).await?,
            Ok(MainMenuChoice::CreateNew) => insert_new(&mut conn).await?,
            Ok(MainMenuChoice::DropDb) => {
                let confirmed_drop =
                    inquire::Confirm::new("Do you really want to drop (delete) the full database?")
                        .with_default(false)
                        .prompt()?;
                if confirmed_drop {
                    let mut rng = rand::thread_rng();
                    let s: [u8; 2] = rng.gen();
                    let answer = inquire::Text::new(
                &format!("To confirm that you *REALLY* want to delete the complete database please compute {} + {} = ",
                            s[0],
                            s[1]
                        )
                    )
                    .with_placeholder("...")
                    .prompt()?;
                    let correct_answer = (s[0] as u16).checked_add(s[1] as u16).ok_or(eyre!(
                        "Internal error; this should not have happened. Please try again"
                    ))?;
                    if answer.parse::<u16>()? == correct_answer {
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
                }
            }
            Err(e) => println!("{}", e),
        }
        println!("");
    }
    Ok(())
}
