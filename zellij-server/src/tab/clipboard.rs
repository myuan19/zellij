use anyhow::Result;
use zellij_utils::{data::CopyDestination, input::options::Clipboard};

use crate::ClientId;

use super::{copy_command::CopyCommand, Output};

pub(crate) enum ClipboardProvider {
    Command(CopyCommand),
    Osc52(Clipboard),
    Auto(Clipboard), // Auto mode: dynamically detect on each copy operation
}

impl ClipboardProvider {
    pub(crate) fn set_content(
        &self,
        content: &str,
        output: &mut Output,
        client_ids: impl Iterator<Item = ClientId>,
        source_client_id: Option<ClientId>, // Client that initiated the copy
        client_x11_available: &std::collections::HashMap<ClientId, bool>, // X11 availability per client
        get_client_display: impl Fn(ClientId) -> Option<String>, // Function to get DISPLAY value for a client
    ) -> Result<()> {
        match &self {
            ClipboardProvider::Command(command) => {
                command.set(content.to_string())?;
            },
            ClipboardProvider::Osc52(clipboard) => {
                let dest = match clipboard {
                    #[cfg(not(target_os = "macos"))]
                    Clipboard::Primary => 'p',
                    #[cfg(target_os = "macos")] // primary selection does not exist on macos
                    Clipboard::Primary => 'c',
                    Clipboard::System => 'c',
                };
                output.add_pre_vte_instruction_to_multiple_clients(
                    client_ids,
                    &format!("\u{1b}]52;{};{}\u{1b}\\", dest, base64::encode(content)),
                );
            },
            ClipboardProvider::Auto(clipboard) => {
                // Check if source client has X11
                let client_has_x11 = if let Some(source_id) = source_client_id {
                    client_x11_available.get(&source_id).copied().unwrap_or(false)
                } else {
                    false
                };
                
                // If client has X11, try to use xclip (it will work through X11 forwarding)
                if client_has_x11 {
                    // Check if xclip is available (don't check server DISPLAY)
                    if std::process::Command::new("xclip")
                        .arg("-version")
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .status()
                        .is_ok()
                    {
                        // Use xclip - it will work through X11 forwarding if client has X11
                        let display_value = if let Some(source_id) = source_client_id {
                            get_client_display(source_id)
                        } else {
                            None
                        };
                        let command = CopyCommand::new("xclip -selection clipboard".to_string());
                        command.set_with_env(content.to_string(), display_value)?;
                    } else {
                        // xclip not available, fallback to OSC52
                        let dest = match clipboard {
                            #[cfg(not(target_os = "macos"))]
                            Clipboard::Primary => 'p',
                            #[cfg(target_os = "macos")]
                            Clipboard::Primary => 'c',
                            Clipboard::System => 'c',
                        };
                        let osc52_sequence = format!("\u{1b}]52;{};{}\u{1b}\\", dest, base64::encode(content));
                        if let Some(source_id) = source_client_id {
                            output.add_pre_vte_instruction_to_client(source_id, &osc52_sequence);
                        } else {
                            output.add_pre_vte_instruction_to_multiple_clients(client_ids, &osc52_sequence);
                        }
                    }
                } else {
                    // Client doesn't have X11, use OSC52
                    let dest = match clipboard {
                        #[cfg(not(target_os = "macos"))]
                        Clipboard::Primary => 'p',
                        #[cfg(target_os = "macos")]
                        Clipboard::Primary => 'c',
                        Clipboard::System => 'c',
                    };
                    let osc52_sequence = format!("\u{1b}]52;{};{}\u{1b}\\", dest, base64::encode(content));
                    if let Some(source_id) = source_client_id {
                        output.add_pre_vte_instruction_to_client(source_id, &osc52_sequence);
                    } else {
                        output.add_pre_vte_instruction_to_multiple_clients(client_ids, &osc52_sequence);
                    }
                }
            },
        };
        Ok(())
    }

    pub(crate) fn as_copy_destination(&self) -> CopyDestination {
        match self {
            ClipboardProvider::Command(_) => CopyDestination::Command,
            ClipboardProvider::Osc52(clipboard) | ClipboardProvider::Auto(clipboard) => {
                match clipboard {
                    Clipboard::Primary => CopyDestination::Primary,
                    Clipboard::System => CopyDestination::System,
                }
            },
        }
    }
}
