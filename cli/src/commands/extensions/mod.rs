use std::collections::HashSet;
use std::ffi::OsStr;
use std::fmt::Display;
use std::fs;
use std::io::ErrorKind;
use std::path::PathBuf;

use ansi_term::Color;
use anyhow::{anyhow, Context, Result};
use clap::{arg, Arg, ArgGroup, ArgMatches, Command, ValueHint};
use dialoguer::console::Term;
use dialoguer::Confirm;
use futures::future::BoxFuture;
use log::{error, warn};

use crate::api::PhylumApi;
use crate::commands::extensions::extension::{Extension, ExtensionManifest};
use crate::commands::{CommandResult, CommandValue, ExitCode};
use crate::print::print_sc_help;
use crate::print_user_success;

pub mod api;
pub mod extension;
pub mod permissions;
pub mod state;

const EXTENSION_SKELETON: &[u8] = b"\
import { PhylumApi } from 'phylum';

console.log('Hello, World!');
";

pub fn command<'a>() -> Command<'a> {
    Command::new("extension")
        .about("Manage extensions")
        .subcommand(
            Command::new("install")
                .about("Install extension")
                .arg(arg!(-y --yes "Accept permissions and overwrite existing (same as --overwrite --accept-permissions)"))
                .arg(Arg::new("accept-permissions").long("accept-permissions").help("Automatically accept requested permissions"))
                .group(
                    ArgGroup::new("accept-permissions-group").args(&["yes", "accept-permissions"]),
                )
                .arg(arg!(--overwrite "Overwrite existing extension"))
                .group(ArgGroup::new("overwrite-group").args(&["yes", "overwrite"]))
                .arg(arg!([PATH]).required(true).value_hint(ValueHint::DirPath)),
        )
        .subcommand(
            Command::new("uninstall").about("Uninstall extension").arg(arg!([NAME]).required(true)),
        )
        .subcommand(
            Command::new("new").about("Create a new extension").arg(arg!([PATH]).required(true)),
        )
        .subcommand(
            Command::new("run")
                .about("Run an extension from a directory")
                .allow_hyphen_values(true)
                .disable_help_flag(true)
                .arg(arg!(-y --yes "Automatically accept requested permissions"))
                .arg(arg!([PATH]).required(true))
                .arg(arg!([OPTIONS] ... "Extension parameters")),
        )
        .subcommand(Command::new("list").about("List installed extensions"))
}

/// Generate the subcommands for each extension.
pub fn add_extensions_subcommands(command: Command<'_>) -> Command<'_> {
    let extensions = match installed_extensions() {
        Ok(extensions) => extensions,
        Err(e) => {
            error!("Couldn't list extensions: {}", e);
            return command;
        },
    };

    let names = command.get_subcommands().map(|n| n.get_name().to_string()).collect::<HashSet<_>>();

    extensions
        .into_iter()
        .filter(|ext| {
            if names.contains(ext.name()) {
                warn!("{}: extension was filtered out due to name conflict", ext.name());
                false
            } else {
                true
            }
        })
        .fold(command, |command, ext| {
            command.subcommand(
                Command::new(ext.name())
                    .allow_hyphen_values(true)
                    .disable_help_flag(true)
                    .arg(arg!([OPTIONS] ... "Extension parameters")),
            )
        })
}

/// Entry point for the `extensions` subcommand.
pub async fn handle_extensions(
    api: BoxFuture<'static, Result<PhylumApi>>,
    matches: &ArgMatches,
    app: &mut Command<'_>,
) -> CommandResult {
    match matches.subcommand() {
        Some(("install", matches)) => {
            handle_install_extension(
                matches.value_of("PATH").unwrap(),
                matches.is_present("accept-permissions-group"),
                matches.is_present("overwrite-group"),
            )
            .await
        },
        Some(("uninstall", matches)) => {
            handle_uninstall_extension(matches.value_of("NAME").unwrap()).await
        },
        Some(("run", matches)) => handle_run_extension_from_path(app, api, matches).await,
        Some(("new", matches)) => handle_create_extension(matches.value_of("PATH").unwrap()).await,
        Some(("list", _)) | None => handle_list_extensions().await,
        _ => unreachable!(),
    }
}

/// Handle the `<extension>` command path.
///
/// Run the extension by name.
pub async fn handle_run_extension(
    api: BoxFuture<'static, Result<PhylumApi>>,
    name: &str,
    args: &ArgMatches,
) -> CommandResult {
    let options = args.get_many("OPTIONS").map(|options| options.cloned().collect());

    let extension = Extension::load(name)?;

    extension.run(api, options.unwrap_or_default()).await?;

    Ok(CommandValue::Code(ExitCode::Ok))
}

/// Handle the `extension run <PATH>` command path.
///
/// Run the extension located at the given path.
pub async fn handle_run_extension_from_path(
    app: &mut Command<'_>,
    api: BoxFuture<'static, Result<PhylumApi>>,
    matches: &ArgMatches,
) -> CommandResult {
    let path = matches.value_of("PATH").unwrap();
    let options = matches.get_many("OPTIONS").map(|options| options.cloned().collect());

    if ["--help", "-h", "help"].contains(&path) {
        print_sc_help(app, &["extension", "run"])?;
        return Ok(CommandValue::Code(ExitCode::Ok));
    }

    let extension_path =
        fs::canonicalize(path).with_context(|| anyhow!("Invalid extension path: {path:?}"))?;
    let extension = Extension::try_from(extension_path)?;

    if !matches.is_present("yes") && !extension.permissions().is_allow_none() {
        ask_permissions(&extension)?;
    }

    extension.run(api, options.unwrap_or_default()).await?;

    Ok(CommandValue::Code(ExitCode::Ok))
}

/// Handle the `extension install` subcommand path.
///
/// Install the extension from the specified path.
async fn handle_install_extension(
    path: &str,
    accept_permissions: bool,
    overwrite: bool,
) -> CommandResult {
    // NOTE: Extension installation without slashes is reserved for the marketplace.
    if !path.contains('/') && !path.contains('\\') {
        return Err(anyhow!("Ambiguous extension URI '{}', use './{0}' instead", path));
    }

    let extension_path = PathBuf::from(path);
    let extension = Extension::try_from(extension_path)?;

    println!("Installing extension {}...", extension.name());

    if !overwrite {
        if let Ok(installed_extension) = Extension::load(extension.name()) {
            if extension == installed_extension {
                print_user_success!(
                    "Extension {} already installed, nothing to do",
                    extension.name()
                );
                return Ok(CommandValue::Code(ExitCode::Ok));
            }
            ask_overwrite(&extension)?;
        }
    }

    if !accept_permissions && !extension.permissions().is_allow_none() {
        ask_permissions(&extension)?;
    }

    extension.install()?;

    print_user_success!("Extension {} installed successfully", extension.name());

    Ok(CommandValue::Code(ExitCode::Ok))
}

fn ask_overwrite(extension: &Extension) -> Result<()> {
    let mut prompt = Confirm::new();
    prompt
        .with_prompt(format!(
            "Another version of the '{}' extension is already installed. Overwrite?",
            extension.name()
        ))
        .default(true);

    // Abort if stdout is not a terminal to avoid hanging CI or other scripts
    if !Term::stdout().is_term() || !prompt.interact()? {
        return Err(anyhow!("install aborted"));
    }

    Ok(())
}

fn ask_permissions(extension: &Extension) -> Result<()> {
    if !Term::stdout().is_term() {
        return Err(anyhow!(
            "Can't ask for permissions: not a terminal. For unsupervised usage, consider using \
             the -y / --yes flag."
        ));
    }

    let permissions = extension.permissions();

    println!("The `{}` extension requires the following permissions:", extension.name());

    fn print_permissions_list<S: Display>(key: &str, resource: &str, items: Option<&Vec<S>>) {
        // Don't prompt if no permissions are requested.
        let permissions = match items {
            Some(permissions) => permissions,
            None => return,
        };

        if permissions.is_empty() {
            let msg = format!("{key} any {resource}");
            println!("\n  {}", Color::Yellow.bold().paint(msg));
        } else {
            println!("\n  {} the following {resource}s:", Color::Blue.bold().paint(key));

            for permission in permissions {
                println!("    '{permission}'");
            }
        }
    }

    print_permissions_list("Read", "path", permissions.read.get());
    print_permissions_list("Write", "path", permissions.write.get());
    print_permissions_list("Run", "command", permissions.run.get());
    print_permissions_list("Access", "domain", permissions.net.get());

    if !Confirm::new().with_prompt("\nDo you accept?").default(false).interact()? {
        Err(anyhow!("permissions not granted, aborting"))
    } else {
        Ok(())
    }
}

/// Handle the `extension uninstall` subcommand path.
///
/// Uninstall the extension named as specified.
async fn handle_uninstall_extension(name: &str) -> CommandResult {
    let extension = match Extension::load(name) {
        Ok(extension) => extension,
        Err(_) => return Err(anyhow!("No extension with name {name:?} installed")),
    };

    extension.uninstall()?;

    Ok(CommandValue::Code(ExitCode::Ok))
}

/// Handle the `extension new` command path.
///
/// Create a new extension in the current directory.
pub async fn handle_create_extension(path: &str) -> CommandResult {
    // Error out when target is already occupied.
    //
    // This allows use to use [`fs::create_dir_all`] without having to worry about
    // reusing an existing directory.
    let extension_path = PathBuf::from(path);
    if extension_path.exists() {
        return Err(anyhow!("Destination {path:?} already exists"));
    }

    // Extract extension name.
    let name = extension_path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| anyhow!("Last segment in {path:?} is not a valid extension name"))?;

    extension::validate_name(name)?;

    // Create all missing directories.
    fs::create_dir_all(&extension_path)
        .with_context(|| format!("Unable to create all directories in {path:?}"))?;

    // Write manifest file.
    let manifest = ExtensionManifest::new(name);
    let manifest_path = extension_path.join("PhylumExt.toml");
    fs::write(manifest_path, toml::to_string(&manifest)?.as_bytes())?;

    // Create "Hello, World!" example.
    let entry_path = extension_path.join("main.ts");
    fs::write(entry_path, EXTENSION_SKELETON)?;

    print_user_success!(
        "\
        Extension created successfully
        \nRun `phylum extension install {path}` to install it."
    );

    Ok(CommandValue::Code(ExitCode::Ok))
}

/// Handle the `extension` / `extension list` subcommand path.
///
/// List installed extensions.
async fn handle_list_extensions() -> CommandResult {
    let extensions = installed_extensions()?;

    if extensions.is_empty() {
        println!("No extensions are currently installed.");
    } else {
        let heading = Color::Blue.paint("Extension Name         Description");
        println!("{heading}");

        for extension in extensions {
            println!("{:20}   {}", extension.name(), extension.description().unwrap_or(""));
        }
    }

    Ok(CommandValue::Code(ExitCode::Ok))
}

/// Return a list of installed extensions. Filter out invalid extensions instead
/// of exiting early.
pub fn installed_extensions() -> Result<Vec<Extension>> {
    let extensions_path = extension::extensions_path()?;

    let dir_entry = match fs::read_dir(extensions_path) {
        Ok(d) => d,
        Err(e) => {
            if e.kind() == ErrorKind::NotFound {
                return Ok(Vec::new());
            } else {
                return Err(e.into());
            }
        },
    };

    Ok(dir_entry
        .filter_map(|dir_entry| {
            match dir_entry
                .map_err(|e| e.into())
                .and_then(|dir_entry| Extension::try_from(dir_entry.path()))
            {
                Ok(ext) => Some(ext),
                Err(e) => {
                    error!("{e}");
                    None
                },
            }
        })
        .collect::<Vec<_>>())
}
