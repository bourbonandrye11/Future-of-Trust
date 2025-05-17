

use std::path::Path;
use crate::error::CustodyError;

/// Metadata extracted from a validated shard filename
pub struct ShardFileMetadata {
    pub participant_id: u8,
    pub filename: String,
}

/// Validates the filename structure and extracts participant ID.
///
/// Enforces:
/// - Format: shard_<n>.bin
/// - `<n>` is a valid u8 number
/// - Ends in `.bin`
pub fn validate_shard_filename(path: &str) -> Result<ShardFileMetadata, CustodyError> {
    let path = Path::new(path);
    let filename = path.file_name()
        .ok_or_else(|| CustodyError::IOError("Missing shard filename".into()))?
        .to_str()
        .ok_or_else(|| CustodyError::IOError("Invalid shard filename encoding".into()))?;

    let parts: Vec<&str> = filename.split('_').collect();
    if parts.len() != 2 || !parts[0].eq("shard") {
        return Err(CustodyError::IOError("Shard filename must start with 'shard_'".into()));
    }

    if !parts[1].ends_with(".bin") {
        return Err(CustodyError::IOError("Shard file must end with '.bin'".into()));
    }

    let index_part = parts[1].trim_end_matches(".bin");

    let id: u8 = index_part.parse()
        .map_err(|_| CustodyError::IOError("Shard filename must end with a number".into()))?;

    Ok(ShardFileMetadata {
        participant_id: id,
        filename: filename.to_string(),
    })
}
