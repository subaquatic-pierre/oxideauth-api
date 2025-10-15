use clap::{Parser, Subcommand};
use std::process::Command;

#[derive(Parser)]
#[clap(name = "oxideauth")]
#[clap(version = "1.0")]
#[clap(about = "A Rust-based Auth Service CLI")]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Start,
    Stop,
}

pub fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Start => {
            println!("Starting the server...");
            // Logic to start the server
            Command::new("cargo")
                .arg("run --bin server")
                .spawn()
                .expect("Failed to start server");
        }
        Commands::Stop => {
            println!("Stopping the server...");
            // Logic to stop the server
            // For simplicity, let's assume we're using a process identifier (PID)
            // In a real-world scenario, you'd have a more sophisticated approach
            let pid = std::fs::read_to_string("server.pid").expect("Failed to read PID file");
            Command::new("kill")
                .arg(pid.trim())
                .spawn()
                .expect("Failed to stop server");
        }
    }
}
