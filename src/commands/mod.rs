pub mod lock;
pub mod unlock;
pub mod change_password;
pub mod check;
pub mod info;

use anyhow::Result;
use crate::cli::{Cli, Command};

pub fn dispatch(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Lock {
            file,
            password,
            password_stdin,
            user_password,
            owner_password,
            no_print,
            no_copy,
            no_edit,
            output,
            in_place,
        } => lock::execute(
            file,
            password,
            password_stdin,
            user_password,
            owner_password,
            no_print,
            no_copy,
            no_edit,
            output,
            in_place,
        ),
        Command::Unlock {
            file,
            password,
            password_stdin,
            output,
            in_place,
        } => unlock::execute(file, password, password_stdin, output, in_place),
        Command::ChangePassword {
            file,
            old,
            new,
            password_stdin,
            output,
            in_place,
        } => change_password::execute(file, old, new, password_stdin, output, in_place),
        Command::Info {
            file,
            json,
        } => info::execute(file, json),
        Command::Check {
            file,
            password,
            password_stdin,
        } => check::execute(file, password, password_stdin),
    }
}
