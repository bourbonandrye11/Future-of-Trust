/// for CLI
/// 

use clap::{Parser, Subcommand};
use custody_engine::{
    init_logging,
    crypto::{keys, signing},
    mpc::SigningSession,
    types::ParticipantId,
};

#[derive(Parser)]
#[command(name = "custody", version = "0.1", author = "Custody Team", about = "Custody MPC CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new MPC key set
    GenerateKeys {
        #[arg(short, long)]
        threshold: usize,
        #[arg(short, long)]
        participants: usize,
    },
    /// sign a message with a sealed shard
    SignMessage {
        #[arg(short, long)]
        participant: u8,

        #[arg(short, long)]
        shard: String,

        #[arg(short, long)]
        msg: String,
    },

    /// Verify a full signature
    VerifySignature {
        #[arg(short, long)]
        pubkey: String,

        #[arg(short, long)]
        sig: String,

        #[arg(short, long)]
        msg: String,
    }
}
fn main() {
    // Initialize structured logging using `tracing`
    // This sets up debug/info/error level logging across the CLI
    init_logging();

     // Parse CLI arguments using clap (see `Cli` and `Commands` structs)
    // This handles subcommands and flags like: `generate-keys`, `sign-message`, etc.
    let cli = Cli::parse();

    // Match against the specific subcommand requested
    // This runs the appropriate custody engine logic
    match cli.command {
         // Subcommand: GenerateKeys
        // Generates a new threshold keyset (sealed shards + public key)
        Commands::GenerateKeys { threshold, participants } => {
            let (shards, pubkey) = keys::generate_and_seal_key_shards(threshold, participants)
                .expect("Failed to generate keys");

                // Output the group public key in hex format
            println!("Group Public Key: {}", hex::encode(pubkey));

            // Write each sealed shard to a binary file for storage
            for (i, shard) in shards.iter().enumerate() {
                let path = format!("shard_{}.bin", i + 1);
                std::fs::write(&path, shard).expect("Failed to write shard");
                println!("saved sealed shard: {}", path);
            }
        }

        // Subcommand: SignMessage
        // Loads a sealed shard, starts a signing session, and generates a partial signature
        Commands::SignMessage { participant, shard, msg } => {
            // Load the sealed shard from disk
            let data = std::fs::read(&shard).expect("Failed to read shard file");
            // Start a signing session for the input message
            let mut session = SigningSession::new(msg.as_bytes().to_vec());
            // Generate fresh nonce for the participant
            session.generate_nonce(ParticipantId(participant)).unwrap();

            // Create a partial signature share
            let sig = session.create_partial_signature(ParticipantId(participant), &data)
                .expect("Failed to create partial signature");

                // Output the partial signature in hex format
            println!("Partial signature: {}", hex::encode(sig.to_bytes()));
        }

        // Subcommand: VerifySignature
        // Verifies a full aggregated Schnorr signature
        Commands::VerifySignature { pubkey, sig, msg } => {
            // Decode inputs from hex
            let pubkey_bytes = hex::decode(pubkey).expect("Invalid pubkey hex");
            let sig_bytes = hex::decode(sig).expect("Invalid signature hex");

            // Run signature verification against the message and public key
            match signing::verify_signature(&pubkey_bytes, msg.as_bytes(), &sig_bytes) {
                Ok(_) => println!("Signature verified"),
                Err(e) => println!("Invalid signature: {}", e),
            }
        }
    }
}