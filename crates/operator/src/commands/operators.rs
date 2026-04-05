//! Operator management commands

use anyhow::Result;

use crate::cli::CliState;
use crate::display::{print_error, print_info, print_success};
use crate::theme::Theme;
use comfy_table::{presets::UTF8_FULL, Cell, Color, ContentArrangement, Table};

/// List all operators
pub async fn list(cli: &CliState) -> Result<()> {
    print_info("Fetching operators...");

    match cli.client.list_operators().await {
        Ok(operators) => {
            if operators.is_empty() {
                print_info("No operators");
                return Ok(());
            }

            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL)
                .set_content_arrangement(ContentArrangement::Dynamic);

            // Headers
            if Theme::is_interactive() {
                table.set_header(vec![
                    Cell::new("ID").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                    Cell::new("Username").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                    Cell::new("Role").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                    Cell::new("Status").fg(Color::Rgb { r: 203, g: 166, b: 247 }),
                ]);
            } else {
                table.set_header(vec!["ID", "Username", "Role", "Status"]);
            }

            // Rows
            for op in &operators {
                let id_short = if let Some(ref id) = op.id {
                    if id.value.len() >= 4 {
                        hex::encode(&id.value[..4])
                    } else {
                        hex::encode(&id.value)
                    }
                } else {
                    "unknown".to_string()
                };

                let status = if op.is_active { "active" } else { "inactive" };

                table.add_row(vec![
                    id_short,
                    op.username.clone(),
                    op.role.clone(),
                    status.to_string(),
                ]);
            }

            println!("{}", table);
            print_info(&format!("{} operator(s)", operators.len()));
        }
        Err(e) => {
            print_error(&format!("Failed to list operators: {}", e));
        }
    }

    Ok(())
}

/// Create a new operator
pub async fn create(cli: &CliState, username: String, password: String, role: String) -> Result<()> {
    print_info(&format!("Creating operator '{}'...", username));

    match cli.client.create_operator(username.clone(), password, role).await {
        Ok(operator) => {
            let id_short = if let Some(ref id) = operator.id {
                if id.value.len() >= 4 {
                    hex::encode(&id.value[..4])
                } else {
                    hex::encode(&id.value)
                }
            } else {
                "unknown".to_string()
            };
            print_success(&format!("Operator '{}' created (ID: {})", username, id_short));
        }
        Err(e) => {
            print_error(&format!("Failed to create operator: {}", e));
        }
    }

    Ok(())
}

/// Update an operator
pub async fn update(cli: &CliState, operator_id: String, role: Option<String>, disabled: Option<bool>) -> Result<()> {
    // Decode operator ID
    let operator_bytes = hex::decode(&operator_id).unwrap_or_else(|_| operator_id.as_bytes().to_vec());

    print_info(&format!("Updating operator {}...", operator_id));

    match cli.client.update_operator(operator_bytes, role, disabled).await {
        Ok(operator) => {
            print_success(&format!("Operator '{}' updated", operator.username));
        }
        Err(e) => {
            print_error(&format!("Failed to update operator: {}", e));
        }
    }

    Ok(())
}

/// Delete an operator
pub async fn delete(cli: &CliState, operator_id: String) -> Result<()> {
    // Decode operator ID
    let operator_bytes = hex::decode(&operator_id).unwrap_or_else(|_| operator_id.as_bytes().to_vec());

    print_info(&format!("Deleting operator {}...", operator_id));

    match cli.client.delete_operator(operator_bytes).await {
        Ok(success) => {
            if success {
                print_success(&format!("Operator {} deleted", operator_id));
            } else {
                print_error("Failed to delete operator");
            }
        }
        Err(e) => {
            print_error(&format!("Failed to delete operator: {}", e));
        }
    }

    Ok(())
}
