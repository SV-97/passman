use eyre::{eyre, Report, Result};
use inquire;
use inquire::ui;
use pwdgen_core::PassSpec;
use secrecy::SecretString;
use sqlx::{Connection, SqliteConnection};

use std::fmt;

// type OwnedPassSpec = PassSpec<String, String>;

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

async fn retrieve_by_name(conn: &mut SqliteConnection, name: &str) -> Result<DbPassSpec> {
    let record = sqlx::query!("SELECT * from domains where name=?", name)
        .fetch_one(conn)
        .await?;
    Ok(DbPassSpec {
        uid: record.uid,
        domain: record.name,
        length: usize::try_from(record.length).map_err(|e| eyre!(e))?,
        prohibited_chars: record.prohibited_characters,
        version: record.version.try_into()?,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    enum MainMenuChoice {
        Query,
        CreateNew,
        Exit,
    }
    impl fmt::Display for MainMenuChoice {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(match self {
                Self::Query => "Query entries",
                Self::CreateNew => "Create a new entry",
                Self::Exit => "Exit",
            })
        }
    }

    let mut conn = SqliteConnection::connect("sqlite://totally_not_my_passwords.db").await?;

    let main_menu_options = vec![
        MainMenuChoice::Query,
        MainMenuChoice::CreateNew,
        MainMenuChoice::Exit,
    ];
    let main_select = inquire::Select::new("Select submenu:", main_menu_options.clone());
    loop {
        let ans = main_select.clone().prompt();
        match ans {
            Ok(MainMenuChoice::Exit) => break,
            Ok(MainMenuChoice::Query) => query(&mut conn).await?,
            Ok(MainMenuChoice::CreateNew) => insert_new(&mut conn).await?,
            Err(e) => println!("{}", e),
        }
    }
    Ok(())
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
