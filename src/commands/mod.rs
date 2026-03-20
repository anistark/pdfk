pub mod change_password;
pub mod check;
pub mod info;
pub mod lock;
pub mod unlock;

use crate::cli::{Cli, Command};
use anyhow::Result;

pub fn dispatch(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Lock {
            files,
            password,
            password_stdin,
            user_password,
            owner_password,
            no_print,
            no_copy,
            no_edit,
            output,
            in_place,
            recursive,
            dry_run,
        } => lock::execute(
            files,
            password,
            password_stdin,
            user_password,
            owner_password,
            no_print,
            no_copy,
            no_edit,
            output,
            in_place,
            recursive,
            dry_run,
        ),
        Command::Unlock {
            files,
            password,
            password_stdin,
            output,
            in_place,
            recursive,
            dry_run,
        } => unlock::execute(
            files,
            password,
            password_stdin,
            output,
            in_place,
            recursive,
            dry_run,
        ),
        Command::ChangePassword {
            files,
            old,
            new,
            password_stdin,
            output,
            in_place,
            recursive,
            dry_run,
        } => change_password::execute(
            files,
            old,
            new,
            password_stdin,
            output,
            in_place,
            recursive,
            dry_run,
        ),
        Command::Info {
            files,
            json,
            recursive,
        } => info::execute(files, json, recursive),
        Command::Check {
            files,
            password,
            password_stdin,
            recursive,
        } => check::execute(files, password, password_stdin, recursive),
    }
}
