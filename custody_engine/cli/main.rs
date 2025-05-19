/// for CLI
/// 

use clap::{Parser, Subcommand, Arg};
use tonic::transport::Channel;
use frost_ed25519::SignatureShare;
use custody_engine::utils::filename::validate_shard_filename;
use custody_engine::audit::{AUDIT, AuditRecord, AuditEventType, now_rfc3339};
use custody_engine::logging::init_logging;
use custody::custody_management_service_client::CustodyManagementServiceClient;
use custody::GetDIDDocumentRequest;
use std::path::Path;
use custody_engine::{
   // init_logging,
    crypto::{keys, signing},
    mpc::SigningSession,
    types::ParticipantId,
};
use crate::proto::custody::custody_client::CustodyClient;
use crate::proto::custodyvc::{
    SignCredentialRequest, StoreCredentialRequest, GetCredentialRequest, RevokeCredentialRequest,
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

    /// Sign a credential using issuer DID
    SignCredential {
        issuer_did: String,
        vc_json: String,
    },
    /// Store a signed credential under a subject DID
    StoreCredential {
        subject_did: String,
        signed_vc_json: String,
    },
    /// Retrieve a stored credential
    GetCredential {
        subject_did: String,
        vc_id: String,
    },
    /// Revoke a stored credential
    RevokeCredential {
        issuer_did: String,
        vc_id: String,
    },

    /// Vault Commands
    GetVcByType {
        vault_id: String,
        vc_type: String,
    },
    DeleteVc {
        vault_id: String,
        vc_id: String,
    },
    GetBbsPrivateKey {
        vault_id: String,
    },
    SetBbsPrivateKey {
        vault_id: String,
        key: String,
    },
    GetBbsPublicKey {
        vault_id: String,
    },
    SetBbsPublicKey {
        vault_id: String,
        key: String,
    },
    GetPublicKeys {
        vault_id: String,
    },
    AddPublicKey {
        vault_id: String,
        key: String,
    },
    RemovePublicKey {
        vault_id: String,
        key: String,
    },

    // Operational DID
    RegisterOpDid {
        operational_did: String,
        root_did: String,
        vault_id: String,
        did_document_path: String,
    },
    GetVaultId {
        operational_did: String,
    },
    GetDidDocument {
        operational_did: String,
    },
    StoreDidDocument {
        operational_did: String,
        did_document_path: String,
    },
    RotateOpDid {
        old_did: String,
        new_did: String,
    },

    // Issuer
    RegisterIssuer {
        issuer_did: String,
        vault_ref: String,
        public_key: String,
    },
    GetIssuer {
        issuer_did: String,
    },
    RemoveIssuer {
        issuer_did: String,
    },
    DeactivateIssuer {
        issuer_did: String,
    },

    GenerateIssuerKeys {
        issuer_did: String,
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

/*
    need to circle back to this part. 
    fn manual_provision_vault(op_did: String, root_did: String) {
    let vault = Vault::new_with_frost_group().unwrap();
    registry.register(OperationalDID(op_did), RootDID(root_did), vault).unwrap();
    println!("Vault manually provisioned.");
}

    we need to add a get-did-document command as well
*/

/*
    use clap::{Command, Arg};
use custody::custody_management_service_client::CustodyManagementServiceClient;
use custody::ProvisionIdentityMaterialRequest;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = Command::new("custody-cli")
        .subcommand(
            Command::new("provision-dkg")
                .about("Trigger DKG provisioning for a new DID")
                .arg(Arg::new("operational_did").required(true))
                .arg(Arg::new("root_did").required(true)),
        )
        .subcommand(
            Command::new("get-mpc-group")
                .about("Get MPC group config for a DID")
                .arg(Arg::new("operational_did").required(true)),
        )
        .get_matches();

    if let Some(sub) = matches.subcommand_matches("provision-dkg") {
        let op_did = sub.get_one::<String>("operational_did").unwrap();
        let root_did = sub.get_one::<String>("root_did").unwrap();

        let mut client = CustodyManagementServiceClient::connect("http://[::1]:50051").await?;
        let response = client.provision_identity_material(ProvisionIdentityMaterialRequest {
            operational_did: op_did.clone(),
            root_did: root_did.clone(),
        }).await?;

        println!("Provisioned DKG for DID {} with public key commitment {:?}", op_did, response.into_inner().public_key_commitment);
    }

    Ok(())
}

if let Some(sub) = matches.subcommand_matches("get-mpc-group") {
    let op_did = sub.get_one::<String>("operational_did").unwrap();

    let mut client = CustodyManagementServiceClient::connect("http://[::1]:50051").await?;
    let response = client.get_mpc_group_descriptor(GetMPCGroupDescriptorRequest {
        operational_did: op_did.clone(),
    }).await?;

    let resp = response.into_inner();
    println!("MPC Group ID: {}", resp.group_id);
    println!("Threshold: {}", resp.threshold);
    println!("Custody Nodes:");
    for node in resp.custody_nodes {
        println!(" - {}", node);
    }
}

    I added these to the Enum but it wants to connect to gRPC and we didn't set this up that way
    on purpose. so adding here for now. 

    pub async fn run_cli(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    // Connect to the Custody Engine gRPC server
    let mut client = CustodyVcClient::connect("http://[::1]:50051").await?;

    match cli.command {
        Commands::SignCredential { issuer_did, vc_json } => {
            let response = client.sign_credential(SignCredentialRequest {
                issuer_did,
                vc_json,
            }).await?;
            println!("Signed VC JSON:\n{}", response.into_inner().signed_vc_json);
        }
        Commands::StoreCredential { subject_did, signed_vc_json } => {
            let response = client.store_credential(StoreCredentialRequest {
                subject_did,
                signed_vc_json,
            }).await?;
            println!("Stored VC successfully: {}", response.into_inner().success);
        }
        Commands::GetCredential { subject_did, vc_id } => {
            let response = client.get_credential(GetCredentialRequest {
                subject_did,
                vc_id,
            }).await?;
            println!("Retrieved VC:\n{}", response.into_inner().signed_vc_json);
        }
        Commands::RevokeCredential { issuer_did, vc_id } => {
            let response = client.revoke_credential(RevokeCredentialRequest {
                issuer_did,
                vc_id,
            }).await?;
            println!("Revoked VC successfully: {}", response.into_inner().success);
        }

        Commands::GetVcByType { vault_id, vc_type } => {
            let mut client = CustodyVcClient::connect("http://[::1]:50051").await?;
            let response = client.get_vc_by_type(GetVcByTypeRequest {
                vault_id,
                vc_type,
            }).await?;
            println!("VC Found:\n{}", response.into_inner().vc_json);
        }

        Commands::DeleteVc { vault_id, vc_id } => {
            let mut client = CustodyVcClient::connect("http://[::1]:50051").await?;
            let response = client.delete_vc(DeleteVcRequest {
                vault_id,
                vc_id,
            }).await?;
            println!("VC Deleted: {}", response.into_inner().success);
        }

        Commands::GetBbsPrivateKey { vault_id } => {
            let mut client = CustodyVcClient::connect("http://[::1]:50051").await?;
            let response = client.get_bbs_private_key(GetBbsKeyRequest {
                vault_id,
            }).await?;
            println!("BBS Private Key:\n{}", response.into_inner().key);
        }

        Commands::SetBbsPrivateKey { vault_id, key } => {
            let mut client = CustodyVcClient::connect("http://[::1]:50051").await?;
            let response = client.set_bbs_private_key(SetBbsKeyRequest {
                vault_id,
                key,
            }).await?;
            println!("Private Key Set: {}", response.into_inner().success);
        }

        Commands::GetBbsPublicKey { vault_id } => {
            let mut client = CustodyVcClient::connect("http://[::1]:50051").await?;
            let response = client.get_bbs_public_key(GetBbsKeyRequest {
                vault_id,
            }).await?;
            println!("BBS Public Key:\n{}", response.into_inner().key);
        }

        Commands::SetBbsPublicKey { vault_id, key } => {
            let mut client = CustodyVcClient::connect("http://[::1]:50051").await?;
            let response = client.set_bbs_public_key(SetBbsKeyRequest {
                vault_id,
                key,
            }).await?;
            println!("Public Key Set: {}", response.into_inner().success);
        }

        Commands::GetPublicKeys { vault_id } => {
            let mut client = CustodyVcClient::connect("http://[::1]:50051").await?;
            let response = client.get_public_keys(GetPublicKeysRequest {
                vault_id,
            }).await?;
            println!("Public Keys:\n{:#?}", response.into_inner().keys);
        }

        Commands::AddPublicKey { vault_id, key } => {
            let mut client = CustodyVcClient::connect("http://[::1]:50051").await?;
            let response = client.add_public_key(AddPublicKeyRequest {
                vault_id,
                key,
            }).await?;
            println!("Public Key Added: {}", response.into_inner().success);
        }

        Commands::RemovePublicKey { vault_id, key } => {
            let mut client = CustodyVcClient::connect("http://[::1]:50051").await?;
            let response = client.remove_public_key(RemovePublicKeyRequest {
                vault_id,
                key,
            }).await?;
            println!("Public Key Removed: {}", response.into_inner().success);
        }

        Commands::RegisterOpDid { operational_did, root_did, vault_id, did_document_path } => {
            let doc_bytes = std::fs::read(did_document_path)?;
            let mut client = CustodyRegistryClient::connect("http://[::1]:50051").await?;
            client.register_operational_did(RegisterOpDidRequest {
                operational_did,
                root_did,
                vault_id,
                did_document: doc_bytes,
            }).await?;
            println!("Operational DID registered.");
        }

        Commands::GetVaultId { operational_did } => {
            let mut client = CustodyRegistryClient::connect("http://[::1]:50051").await?;
            let response = client.get_vault_for_operational_did(GetVaultForOpDidRequest {
                operational_did,
            }).await?;
            println!("Vault ID: {}", response.into_inner().vault_id);
        }

        Commands::GetDidDocument { operational_did } => {
            let mut client = CustodyRegistryClient::connect("http://[::1]:50051").await?;
            let response = client.get_did_document(GetDidDocumentRequest {
                operational_did,
            }).await?;
            std::fs::write("did_document.json", &response.into_inner().did_document)?;
            println!("Wrote DID document to did_document.json");
        }

        Commands::StoreDidDocument { operational_did, did_document_path } => {
            let doc_bytes = std::fs::read(did_document_path)?;
            let mut client = CustodyRegistryClient::connect("http://[::1]:50051").await?;
            client.store_did_document(StoreDidDocumentRequest {
                operational_did,
                did_document: doc_bytes,
            }).await?;
            println!("DID document stored.");
        }

        Commands::RotateOpDid { old_did, new_did } => {
            let mut client = CustodyRegistryClient::connect("http://[::1]:50051").await?;
            client.rotate_operational_did(RotateOperationalDidRequest {
                old_did,
                new_did,
            }).await?;
            println!("Operational DID rotated.");
        }

        // Issuer Registry CLI

        Commands::RegisterIssuer { issuer_did, vault_ref, public_key } => {
            let mut client = CustodyRegistryClient::connect("http://[::1]:50051").await?;
            client.register_issuer(RegisterIssuerRequest {
                issuer_did,
                vault_ref,
                public_key,
            }).await?;
            println!("Issuer registered.");
        }

        Commands::GetIssuer { issuer_did } => {
            let mut client = CustodyRegistryClient::connect("http://[::1]:50051").await?;
            let resp = client.get_issuer(GetIssuerRequest {
                issuer_did,
            }).await?.into_inner();
            println!("Vault: {}\nPublic Key: {}\nActive: {}", resp.vault_ref, resp.public_key, resp.active);
        }

        Commands::RemoveIssuer { issuer_did } => {
            let mut client = CustodyRegistryClient::connect("http://[::1]:50051").await?;
            client.remove_issuer(RemoveIssuerRequest { issuer_did }).await?;
            println!("Issuer removed.");
        }

        Commands::DeactivateIssuer { issuer_did } => {
            let mut client = CustodyRegistryClient::connect("http://[::1]:50051").await?;
            client.deactivate_issuer(DeactivateIssuerRequest { issuer_did }).await?;
            println!("Issuer deactivated.");
        }

        Commands::GenerateIssuerKeys { issuer_did } => {
        let mut client = CustodyVcClient::connect("http://[::1]:50051").await?;
        let response = client.generate_issuer_keys(GenerateIssuerKeysRequest {
            issuer_did,
        }).await?;
        println!("Issuer public key:\n{}", response.into_inner().public_key);
        }
    }
    Ok(())
}

*/