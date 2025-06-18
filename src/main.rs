use anyhow::Result;
use base64::prelude::*;
use sct::{Log as SctLog, verify_sct};
use std::{collections::HashMap, time::SystemTime};
use x509_parser::{
    certificate::X509Certificate,
    prelude::{FromDer, ParsedExtension},
};

struct CTLog {
    description: String,
    url: String,
    operated_by: String,
    key: Vec<u8>,
    id: [u8; 32],
    max_merge_delay: usize,
}

fn parse_ct_log_list() -> Result<HashMap<[u8; 32], CTLog>> {
    let mut ct_logs_map = HashMap::new();

    let google_ct_logs = include_str!("google_ct_log_list.json");
    let google_ct_logs = serde_json::from_str::<serde_json::Value>(google_ct_logs)?;

    let operators = google_ct_logs
        .get("operators")
        .ok_or(anyhow::anyhow!("Failed to get operators from ct logs"))?
        .as_array()
        .ok_or(anyhow::anyhow!(
            "Failed to get array of operators from ct logs"
        ))?
        .clone();

    for operator in operators {
        let logs = operator
            .get("logs")
            .ok_or(anyhow::anyhow!("Failed to get logs from ct logs"))?
            .as_array()
            .ok_or(anyhow::anyhow!("Failed to get array of logs from ct logs"))?
            .clone();
        for log in logs.clone() {
            let id: &[u8] = &BASE64_STANDARD.decode(
                log.get("log_id")
                    .ok_or(anyhow::anyhow!("Failed to get log_id from ct logs"))?
                    .as_str()
                    .ok_or(anyhow::anyhow!("Failed to get log_id str from ct logs"))?,
            )?;

            let curr_log = CTLog {
                description: log
                    .get("description")
                    .ok_or(anyhow::anyhow!("Failed to get description from ct logs"))?
                    .to_string(),
                url: log
                    .get("url")
                    .ok_or(anyhow::anyhow!("Failed to get url from ct logs"))?
                    .to_string(),
                operated_by: operator
                    .get("name")
                    .ok_or(anyhow::anyhow!("Failed to get name from ct logs"))?
                    .to_string(),
                key: BASE64_STANDARD.decode(
                    log.get("key")
                        .ok_or(anyhow::anyhow!("Failed to get key from ct logs"))?
                        .as_str()
                        .ok_or(anyhow::anyhow!("Failed to get key str from ct logs"))?,
                )?,
                id: id.try_into()?,
                max_merge_delay: log
                    .get("mmd")
                    .ok_or(anyhow::anyhow!("Failed to get mmd from ct logs"))?
                    .as_u64()
                    .ok_or(anyhow::anyhow!("Failed to get mmd str from ct logs"))?
                    .try_into()?,
            };

            ct_logs_map.insert(id.try_into()?, curr_log);
        }
    }

    Ok(ct_logs_map)
}

fn main() -> Result<()> {
    // duckduckgo.com certificate in PEM format
    let key = "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";
    let raw_cert = BASE64_STANDARD.decode(key)?;

    let Ok((_rem, x509cert)) = X509Certificate::from_der(&raw_cert) else {
        anyhow::bail!("Server Certificate Verification Failed: x509 - Bad Encoding.");
    };

    // Due to weird formatting for Log in SCT create a seperate list first
    let log_list = parse_ct_log_list()?;

    for extension in x509cert.extensions() {
        if extension.oid.to_id_string() == "1.3.6.1.4.1.11129.2.4.2".to_string() {
            if let ParsedExtension::SCT(scts) = extension.parsed_extension() {
                println!("ext raw {:?}", extension);
                let mut index: usize = 6;
                for sct in scts {
                    // This is unnecissary, could just pass the whole of the Log in rather than the one
                    // that matches, but did this to eliminate one possible error
                    let tmp_ct_log = log_list.get(sct.id.key_id).unwrap();
                    let tmp_log = SctLog {
                        description: &tmp_ct_log.description,
                        url: &tmp_ct_log.url,
                        operated_by: &tmp_ct_log.operated_by,
                        key: &tmp_ct_log.key,
                        id: tmp_ct_log.id,
                        max_merge_delay: tmp_ct_log.max_merge_delay,
                    };

                    // It seems like `verify_sct` wants just the raw SCT extension, after the length of the extension
                    let length: usize =
                        u16::from_be_bytes(extension.value[index..index + 2].try_into().unwrap())
                            as usize;
                    index += 2;
                    let sct_raw: &[u8] = &extension.value[index..index + length];
                    index += length;

                    let now = SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();

                    if let Err(error) = verify_sct(&raw_cert, sct_raw, now, &[&tmp_log]) {
                        println!("{:?} :: {}", error, "Failed to verify sct");
                    }
                }
            } else {
                anyhow::bail!("Failed to parse SCT extension");
            }
        }
    }

    Ok(())
}
