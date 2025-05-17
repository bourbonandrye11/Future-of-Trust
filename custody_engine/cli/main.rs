/// for CLI
/// 

use clap::{Parser, Subcommand};
use frost_ed25519::SignatureShare;
use custody_engine::utils::filename::validate_shard_filename;
use custody_engine::audit::{AUDIT, AuditRecord, AuditEventType, now_rfc3339};
use custody_engine::logging::init_logging;
use std::path::Path;
use custody_engine::{
   // init_logging,
    crypto::{keys, signing},
    mpc::SigningSession,
    types::ParticipantId,
};

#[derive(Parser)]
#[command(name = "custody", version = "0.1", author = "Custody Team", about = "Custody MPC CLI")]
struct Cli {
    #[arg(long, default_value = "tee-sim", help = "Vault mode: memory | tee-sim")]
    vault: String, // New flag
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

    /// Aggregate multiple partial signature shares into one final signature
    AggregateSignature {
        #[arg(short, long, help = "Hex-encoded partial signatures")]
        shares: Vec<String>, // e.g., --shares abcd --shares efgh

        #[arg(short, long, help = "Original message that was signed")]
        msg: String,
    },
}
fn main() {
    // Initialize structured logging using `tracing`
    // This sets up debug/info/error level logging across the CLI
    // Log to ./logs in logfmt format (change `true` for JSON)
    init_logging("logs", false);

    // choose the vault mode based on CLI flag
    let vault_mode = match cli.vault.as_str() {
        "memory" => VaultMode::Memory,
        "tee-sim" => VaultMode::SimulatedTee,
        other => {
            eprintln!("Unknown vault mode: {}", other);
            std::process::exit(1);
        }
    };

    // Initialize vault engine
    custody_engine::vault::init(vault_mode);

    // enforces filename starts with shard_ | ends with .bin | contains numeric index | blocks .json .txt etc
    match validate_shard_filename(&shard_path) {
        Ok(meta) => {
            println!("Parsed shard file: participant {}", meta.participant_id);
        }
        Err(e) => {
            eprintln!("Invalid shard file: {}", e);
            std::process::exit(1);
        }
    }

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

            AUDIT.log(AuditRecord {
                event_type: AuditEventType::Keygen,
                session_id: hex::encode(&group_public_key), // Or a UUID if generated
                participant_id: None,
                message: format!("Generated {} shards with threshold {}", participants, threshold),
                timestamp: now_rfc3339(),
            });            
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

            if session.submitted_participants.contains(&participant_id) {
                eprintln!("Participant {} already signed for this session", participant_id.0);
                std::process::exit(1);
            }            

            // Create a partial signature share
            let sig = session.create_partial_signature(ParticipantId(participant), &data)
                .expect("Failed to create partial signature");

                // Output the partial signature in hex format
            println!("Partial signature: {}", hex::encode(sig.to_bytes()));

            fn validate_shard_filename(path: &str) -> Result<(), String> {
                let path = Path::new(path);
                let filename = path.file_name()
                    .ok_or("Missing shard filename")?
                    .to_str()
                    .ok_or("Invalid shard filename")?;
            
                // Enforce pattern: shard_<N>.bin
                let parts: Vec<&str> = filename.split('_').collect();
                if parts.len() != 2 || !parts[0].eq("shard") {
                    return Err("Shard filename must start with 'shard_'".into());
                }
            
                if !parts[1].ends_with(".bin") {
                    return Err("Shard file must end with '.bin'".into());
                }
            
                let index_part = parts[1].trim_end_matches(".bin");
                index_part
                    .parse::<u8>()
                    .map_err(|_| "Shard filename must end with a number".into())?;
            
                Ok(())
            }

            AUDIT.log(AuditRecord {
                event_type: AuditEventType::Signing,
                session_id,
                participant_id: Some(participant),
                message: format!("Signed message of {} bytes", msg.len()),
                timestamp: now_rfc3339(),
            });            
        }

        Commands::AggregateSignature { shares, msg } => {
            // Step 1: Parse all partial signatures from hex
            let parsed_shares: Result<Vec<SignatureShare>, _> = shares
                .iter()
                .map(|s| {
                    // turns the hex string into a byte array (Vec<u8>) - required for deserializing signature shares.
                    let bytes = hex::decode(s)
                        .map_err(|e| format!("Invalid hex: {}", e))?;
                    // converts raw bytes into a signatureShare object that the custody engine understands.
                    SignatureShare::from_bytes(&bytes)
                        .map_err(|e| format!("Invalid signature share: {:?}", e))
                })
                .collect();

            let partials = match parsed_shares {
                Ok(sigs) => sigs,
                Err(e) => {
                    eprintln!("Failed to parse signature shares: {}", e);
                    std::process::exit(1);
                }
            };

            // Step 2: Create dummy session to call aggregation (no state needed here)
            let session = SigningSession:new(msg.Clone().into_bytes(), partials.len());

            // Step 3: Aggregate the shares into a final signature
            let result = session.aggregate_partial_signatures(partials);

            let signature = match result {
                Ok(sig) => sig,
                Err(e) => {
                    eprintln!("Aggregation failed: {:?}", e);
                    std::process::exit(1);
            }
        };

        // Step 4: Print the final aggregated signature for CLI output
    println!("Final Signature (hex): {}", hex::encode(signature.to_bytes()));

    AUDIT.log(AuditRecord {
        event_type: AuditEventType::Aggregation,
        session_id: blake3::hash(msg.as_bytes()).to_hex().to_string(),
        participant_id: None,
        message: format!("Aggregated {} shares into final signature", shares.len()),
        timestamp: now_rfc3339(),
    });    
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

            AUDIT.log(AuditRecord {
                event_type: AuditEventType::Verification,
                session_id: blake3::hash(msg.as_bytes()).to_hex().to_string(),
                participant_id: None,
                message: "Successfully verified aggregated signature".into(),
                timestamp: now_rfc3339(),
            });            
        }
    }
}

// cargo run -p cli -- generate-keys --threshold 2 --participants 3 --vault tee-sim
// --vault memory
// cargo run -p cli -- aggregate-signature --shares abcd --shares efgh --msg "hello" --vault tee-sim
