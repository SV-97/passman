// DATABASE_URL="" cargo sqlx prepare
use eyre::{eyre, Report, Result};
use inquire;
use inquire::ui;
use pwdgen_core::PassSpec;
use rand::Rng;
use secrecy::SecretString;
use sqlx::{
    migrate::{Migrate, Migrator},
    sqlite::SqliteConnectOptions,
    ConnectOptions, SqliteConnection,
};

use std::{collections::HashSet, fmt, str::FromStr, time::Duration};

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");
const DATABASE_URL: &'static str = "sqlite://passman.db";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum PwVersion {
    Zero,
}

impl TryFrom<String> for PwVersion {
    type Error = Report;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.as_str() {
            "0" => Ok(Self::Zero),
            // "1" => Ok(Self::One),
            v => Err(eyre!("Unknown version: {}", v)),
        }
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

async fn insert_new(conn: &mut SqliteConnection) -> Result<()> {
    let domain = inquire::Text::new("What's the name of the domain you want to add?").prompt()?;
    let length = inquire::Text::new("How long do you want the password to be?").prompt()?;
    let prohibited_chars =
        inquire::Text::new("What characters (if any) should **not** be part of the password?")
            .prompt()?;
    // we hardcode the version to 0 for now
    sqlx::query!(
        "
        INSERT INTO domains (name, length, prohibited_characters, version)
        VALUES (?, ?, ?, '0');
        ",
        domain,
        length,
        prohibited_chars,
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
                Self::Update => "Update domain",
                Self::Delete => "Delete entry",
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
                println!("Generated password: >>{}<<", pass);
            }
            QueryChoice::Delete => deletion_dialog(conn, selected_domain).await?,
            QueryChoice::Update => update_entry(conn, selected_domain).await?,
        }
    }
    Ok(())
}

fn get_pass(spec: DbPassSpec) -> Result<String> {
    let master_pw = SecretString::new(inquire::Password::new("Master password:").prompt()?);
    match spec.version {
        PwVersion::Zero => {
            let spec = PassSpec {
                domain: spec.domain,
                length: spec.length,
                prohibited_chars: spec.prohibited_chars,
            };
            Ok(spec.gen_v0("just_another_salt", &master_pw))
        }
    }
}

async fn update_entry(conn: &mut SqliteConnection, spec: DbPassSpec) -> Result<()> {
    enum UpdateChoice {
        ModifyProhibitedChars,
    }
    impl fmt::Display for UpdateChoice {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(match self {
                Self::ModifyProhibitedChars => "Modify prohibited chars",
            })
        }
    }

    let choices = vec![UpdateChoice::ModifyProhibitedChars];
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
        }
    }
    Ok(())
}

async fn deletion_dialog(conn: &mut SqliteConnection, spec: DbPassSpec) -> Result<()> {
    let confirmed_delete = inquire::Confirm::new(&format!(
        "Do you really want to remove the entry for domain '{}'?",
        spec.domain
    ))
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
    }
    Ok(())
}
