use std::fs;
use std::path::Path;
use std::io::{self, Write};
use pqcrypto_sphincsplus::sphincssha2128fsimple::{
    keypair, detached_sign, verify_detached_signature,
    PublicKey, SecretKey,
};
use pqcrypto_traits::sign::{PublicKey as PublicKeyTrait, SecretKey as SecretKeyTrait, DetachedSignature};
use reqwest::blocking::Client;
use reqwest::header;
use serde_json::{json, Value};
use serde::{Serialize, Deserialize};
use bincode;

use blake3;
use hex::{encode, decode};
use dialoguer::{Input, Select, Confirm};

use rusqlite::{params, Connection, Result};
use std::sync::mpsc;
use std::thread;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Wallet {
    name: String,
    public_key: String,
    secret_key: String,
    address: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct INTXO {
    txid: String,
    vout: u32,
    extrasize: String,
    extra: String,
    sequence: u64,
}

#[derive(Serialize, Deserialize, Debug)]
struct RawTransaction {
    inputcount: String,
    inputs: Vec<INTXO>,
    outputcount: String,
    outputs: Vec<(String, u64)>,
    fee: u64,
    sigpub: String,
    signature: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct Block {
    height: u64,
    hash: String,
    prev_hash: String,
    timestamp: u64,
    nonce: String,
    transactions: String,
    miner: String,
    difficulty: u64,
    block_reward: u64,
    state_root: String,
    receipts_root: String,
    logs_bloom: String,
    extra_data: String,
    version: u32,
    signature: String,
}

#[derive(Debug)]
struct UnspentUTXO {
    txid: String,
    vout: u32,
    amount: u64,
    block_hash: Option<String>,
    block_height: Option<u64>,
    status: String,
}

fn start_rpc_server(tx: mpsc::Sender<String>) {
    use std::net::TcpListener;
    use std::io::{BufReader, BufRead, Read};
    use std::thread;
    
    thread::spawn(move || {
        let listener = TcpListener::bind("127.0.0.1:40407").expect("Cannot bind RPC port");
        println!("\nListening for RPC on http://127.0.0.1:40407/rpc");

        for stream in listener.incoming() {
            if let Ok(mut stream) = stream {
                let mut buffer = String::new();
                stream.read_to_string(&mut buffer).unwrap_or(0);

				if let Some(start) = buffer.find('{') {
					let json_body = &buffer[start..];
					if let Ok(req) = serde_json::from_str::<Value>(json_body) {
						if req["method"] == "transfer" {
							if let Some(destinations) = req["params"]["destinations"].as_array() {
								let mut cmd = String::from("send");
								for dest in destinations {
									if let (Some(addr), Some(amount)) = (
										dest.get("address").and_then(|a| a.as_str()),
										dest.get("amount").and_then(|a| a.as_u64()),
									) {
										let amount_omi = amount as f64 / 100_000_000.0;
										cmd.push_str(&format!(" {} {:.8}", addr, amount_omi));
									}
								}
								println!("\n[RPC] Injecting command: {}", cmd);
								let _ = tx.send(cmd);
							}
						}
					}
				}


                let response = r#"{"jsonrpc": "2.0", "result": "ok", "id": "0"}"#;
                let http_response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    response.len(),
                    response
                );
                let _ = stream.write_all(http_response.as_bytes());
            }
        }
    });
}


fn init_wallet_db(wallet_name: &str) -> Result<Connection> {
    let db_path = format!("wallets/{}.dat", wallet_name);
    let conn = Connection::open(db_path)?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT
        )",
        [],
    )?;

    conn.execute(
        "INSERT OR IGNORE INTO meta (key, value) VALUES ('last_block', '1')",
        [],
    )?;
    
    conn.execute(
        "CREATE TABLE IF NOT EXISTS inputs (
            txid TEXT,
            vout INTEGER,
            amount INTEGER,
            status TEXT,
            block_hash TEXT,
            block_height INTEGER,
            PRIMARY KEY (txid, vout)
        )",
        [],
    )?;

    Ok(conn)
}

fn get_last_block(conn: &Connection) -> u64 {
    conn.query_row(
        "SELECT value FROM meta WHERE key = 'last_block'",
        [],
        |row| row.get::<_, String>(0),
    )
    .ok()
    .and_then(|s| s.parse().ok())
    .unwrap_or(1)
}

fn update_last_block(conn: &Connection, height: u64) {
    let _ = conn.execute(
        "UPDATE meta SET value = ?1 WHERE key = 'last_block'",
        params![height.to_string()],
    );
}

fn insert_input(
    conn: &Connection, 
    txid: &str, 
    vout: u32, 
    amount: u64, 
    status: &str,
    block_hash: Option<&str>,
    block_height: Option<u64>,
) {
    let _ = conn.execute(
        "INSERT OR IGNORE INTO inputs (txid, vout, amount, status, block_hash, block_height) 
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            txid, 
            vout, 
            amount, 
            status,
            block_hash,
            block_height
        ],
    );
}

fn get_balance(conn: &Connection) -> u64 {
    conn.query_row(
        "SELECT SUM(amount) FROM inputs WHERE status IN ('unspent')",
        [],
        |row| row.get::<_, u64>(0),
    )
    .unwrap_or(0)
}

fn get_unconfirmed_balance(conn: &Connection) -> u64 {
    conn.query_row(
        "SELECT SUM(amount) FROM inputs WHERE status IN ('unconfirmed')",
        [],
        |row| row.get::<_, u64>(0),
    )
    .unwrap_or(0)
}

fn get_unspent_utxos(conn: &Connection) -> Result<Vec<UnspentUTXO>> {
    let mut stmt = conn.prepare(
        "SELECT txid, vout, amount, block_hash, block_height, status 
         FROM inputs 
         WHERE status IN ('unspent') 
         ORDER BY amount DESC"
    )?;
    
    let utxo_iter = stmt.query_map([], |row| {
        Ok(UnspentUTXO {
            txid: row.get(0)?,
            vout: row.get(1)?,
            amount: row.get(2)?,
            block_hash: row.get(3)?,
            block_height: row.get(4)?,
            status: row.get(5)?,
        })
    })?;

    let mut utxos = Vec::new();
    for utxo in utxo_iter {
        utxos.push(utxo?);
    }
    Ok(utxos)
}

fn select_utxos(utxos: &[UnspentUTXO], amount: u64, fee_per_input: u64) -> (Vec<&UnspentUTXO>, u64, u64) {
    let mut best_solution = Vec::new();
    let mut best_total = 0;
    let mut best_fee = 0;

    for utxo in utxos {
        let fee = fee_per_input;
        if utxo.amount >= amount + fee {
            return (vec![utxo], utxo.amount, fee);
        }
    }
    for i in 0..utxos.len() {
        let mut selected = Vec::new();
        let mut total = 0;
        let mut fee = 0;

        for j in i..utxos.len() {
            let utxo = &utxos[j];
            selected.push(utxo);
            total += utxo.amount;
            fee = selected.len() as u64 * fee_per_input;

            if total >= amount + fee {
                if best_solution.is_empty() || selected.len() < best_solution.len() {
                    best_solution = selected.clone();
                    best_total = total;
                    best_fee = fee;
                }
                break;
            }
        }
    }

    (best_solution, best_total, best_fee)
}

fn build_transaction(
    selected_utxos: &[&UnspentUTXO],
    amounts: Vec<u64>,
    fee: u64,
    dest_addresses: Vec<&str>,
    my_address: &str,
) -> (Vec<(String, u32, u64)>, Vec<(String, u64)>, u64) {
    let total_inputs: u64 = selected_utxos.iter().map(|u| u.amount).sum();
    let total_outputs: u64 = amounts.iter().sum();
    let change = total_inputs.checked_sub(total_outputs + fee).unwrap_or(0);
    
    let inputs: Vec<(String, u32, u64)> = selected_utxos
        .iter()
        .map(|u| (u.txid.clone(), u.vout, u.amount))
        .collect();

    let mut outputs = Vec::new();

    for (addr, amount) in dest_addresses.iter().zip(amounts.iter()) {
        outputs.push((addr.to_string(), *amount));
    }

    if change > 0 {
        outputs.push((my_address.to_string(), change));
    }

    (inputs, outputs, fee)
}

fn save_wallet(wallet: &Wallet) -> io::Result<()> {
    let wallet_dir = "wallets";
    if !Path::new(wallet_dir).exists() {
        fs::create_dir(wallet_dir)?;
    }
    let filename = format!("wallets/{}.wallet", wallet.name);
    if Path::new(&filename).exists() {
        return Err(io::Error::new(io::ErrorKind::AlreadyExists, "Wallet already exists"));
    }
    let data = serde_json::to_string_pretty(wallet)?;
    let mut file = fs::File::create(filename)?;
    file.write_all(data.as_bytes())?;
    Ok(())
}

fn load_wallet(name: &str) -> io::Result<Wallet> {
    let filename = format!("wallets/{}.wallet", name);
    let data = fs::read_to_string(filename)?;
    let wallet: Wallet = serde_json::from_str(&data)?;
    Ok(wallet)
}

fn list_wallets() -> io::Result<Vec<String>> {
    let wallet_dir = "wallets";
    if !Path::new(wallet_dir).exists() {
        return Ok(Vec::new());
    }
    let mut wallets = Vec::new();
    for entry in fs::read_dir(wallet_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() && path.extension().map_or(false, |ext| ext == "wallet") {
            if let Some(stem) = path.file_stem() {
                if let Some(name) = stem.to_str() {
                    wallets.push(name.to_string());
                }
            }
        }
    }
    Ok(wallets)
}

fn print_help() {
    println!("Available commands:");
    println!("  help          - Show this help message");
    println!("  balance       - Show current wallet balance");
    println!("  unspent_utxo  - Show all unspent transaction outputs");
    println!("  send <addr1> <amount1> [addr2 amount2 ...] - Send to multiple addresses");
}

fn input_thread(running: Arc<AtomicBool>, tx: mpsc::Sender<String>) {
    while running.load(Ordering::Relaxed) {
        let mut input = String::new();
        print!("> ");
        io::stdout().flush().unwrap();
        io::stdin().read_line(&mut input).unwrap();
        let input = input.trim().to_string();
        if !input.is_empty() {
            tx.send(input).unwrap();
        }
    }
}

fn check_confirm_utxos(conn: &Connection, client: &Client) {
    let mut stmt = conn.prepare(
        "SELECT txid, vout, block_height FROM inputs 
         WHERE status = 'unconfirmed' 
         AND block_height IS NOT NULL 
         AND block_height <= (SELECT value FROM meta WHERE key = 'last_block') - 6"
    ).unwrap();
	
    let utxos = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, u32>(1)?,
            row.get::<_, u64>(2)?
        ))
    }).unwrap();

    for utxo in utxos {
        let (txid, vout, block_height) = utxo.unwrap();
        let request = json!({
            "jsonrpc": "2.0",
            "id": "pokio_wallet",
            "method": "pokio_getBlockByHeight",
            "params": [block_height.to_string()]
        });
        
        if let Ok(resp) = client.post("http://localhost:40404/rpc")
            .header(header::CONTENT_TYPE, "application/json")
            .json(&request)
            .send() 
        {
            if let Ok(response_text) = resp.text() {
                if let Ok(json_response) = serde_json::from_str::<Value>(&response_text) {
                    if let Some(result) = json_response.get("result") {
                        if let Some(block) = result.as_object() {
                            if let Some(txs) = block.get("transactions") {
                                if let Some(tx_str) = txs.as_str() {
                                    if tx_str.split('-').any(|tx| {
                                        let tx_hash = blake3::hash(tx.as_bytes());
                                        hex::encode(tx_hash.as_bytes()) == txid
                                    }) {
                                        conn.execute(
                                            "UPDATE inputs SET status = 'unspent' 
                                             WHERE txid = ?1 AND vout = ?2",
                                            params![txid, vout],
                                        ).unwrap();
                                    } else {
                                        conn.execute(
                                            "DELETE FROM inputs 
                                             WHERE txid = ?1 AND vout = ?2",
                                            params![txid, vout],
                                        ).unwrap();
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn main() {
    println!("\nOMINIRA WALLET 1.0 - SPHINCS+\n");
    let choices = vec![
        "Create new wallet",
        "Load from keys",
        "Load existing wallet",
    ];
    let selection = Select::new()
        .with_prompt("Select an option")
        .items(&choices)
        .default(0)
        .interact()
        .unwrap();
    let (pk, sk, address, wallet_name_opt) = match selection {
        0 => {
            let name: String = loop {
                let name = Input::new()
                    .with_prompt("Name for the new wallet")
                    .interact_text()
                    .unwrap();

                if !Path::new(&format!("wallets/{}.wallet", name)).exists() {
                    break name;
                }
                println!("A wallet with that name already exists. Please choose another.");
            };

            println!("\nGenerating new keys...");
            let (pk, sk) = keypair();
            let address_hash = blake3::hash(pk.as_bytes());
            let address = encode(address_hash.as_bytes());

            let wallet = Wallet {
                name: name.clone(),
                public_key: encode(pk.as_bytes()),
                secret_key: encode(sk.as_bytes()),
                address: address.clone(),
            };

            match save_wallet(&wallet) {
                Ok(_) => println!("Wallet '{}' created successfully", name),
                Err(e) => {
                    println!("Error saving wallet: {}", e);
                    std::process::exit(1);
                }
            }

            (pk, sk, address, Some(name))
        }
        1 => {
            let sk_hex: String = Input::new()
                .with_prompt("Enter private key (hex)")
                .interact_text()
                .unwrap();

            let pk_hex: String = Input::new()
                .with_prompt("Enter public key (hex)")
                .interact_text()
                .unwrap();

            let sk_bytes = decode(sk_hex).expect("Invalid hex for private key");
            let pk_bytes = decode(pk_hex).expect("Invalid hex for public key");

            let sk = SecretKey::from_bytes(&sk_bytes).expect("Failed to create SecretKey");
            let pk = PublicKey::from_bytes(&pk_bytes).expect("Failed to create PublicKey");

            let test_message = b"Test message for key verification";
            let test_sig = detached_sign(test_message, &sk);

            match verify_detached_signature(&test_sig, test_message, &pk) {
                Ok(_) => println!("Valid key pair"),
                Err(e) => {
                    println!("Error: Private and public keys don't form a valid pair");
                    println!("Details: {}", e);
                    std::process::exit(1);
                }
            }

            let address_hash = blake3::hash(pk.as_bytes());
            let address = encode(address_hash.as_bytes());

            (pk, sk, address, None)
        }
        2 => {
            let wallets = match list_wallets() {
                Ok(w) if !w.is_empty() => w,
                _ => {
                    println!("No saved wallets found. Create one first.");
                    std::process::exit(1);
                }
            };

            let selection = Select::new()
                .with_prompt("Select a wallet")
                .items(&wallets)
                .interact()
                .unwrap();

            let wallet_name = &wallets[selection];
            let wallet = match load_wallet(wallet_name) {
                Ok(w) => w,
                Err(e) => {
                    println!("Error loading wallet: {}", e);
                    std::process::exit(1);
                }
            };

            println!("Wallet '{}' loaded successfully", wallet_name);

            let sk_bytes = decode(wallet.secret_key).expect("Invalid hex for private key");
            let pk_bytes = decode(wallet.public_key).expect("Invalid hex for public key");

            let sk = SecretKey::from_bytes(&sk_bytes).expect("Failed to create SecretKey");
            let pk = PublicKey::from_bytes(&pk_bytes).expect("Failed to create PublicKey");

            (pk, sk, wallet.address, Some(wallet_name.clone()))
        }
        _ => unreachable!(),
    };

    println!("\n- View key: {}", encode(pk.as_bytes()));
    println!("- Spend key: {}", encode(sk.as_bytes()));
    println!("- Recover key: {}+{}\n", encode(sk.as_bytes()), encode(pk.as_bytes()));
    println!("\n- Address: {}\n", address);

    let client = Client::builder()
        .gzip(true)
        .build()
        .expect("Error creating HTTP client");

    let (mut last_block, conn) = if let Some(wallet_name) = &wallet_name_opt {
        let conn = init_wallet_db(wallet_name).expect("Failed to open wallet DB");
        (get_last_block(&conn), Some(conn))
    } else {
        (1, None)
    };

    let running = Arc::new(AtomicBool::new(true));
    let (tx, rx) = mpsc::channel();
    let input_running = running.clone();
	
	start_rpc_server(tx.clone());
    
    thread::spawn(move || {
        input_thread(input_running, tx);
    });

    loop {
        if let Ok(cmd) = rx.try_recv() {
            let parts: Vec<&str> = cmd.split_whitespace().collect();
            match parts.as_slice() {
                ["help"] => print_help(),
                ["balance"] => {
                    if let Some(ref conn) = conn {
                        let balance = get_balance(conn);
                        println!("\nBalance: {} OMI", balance as f64 / 100000000.0);
						let ubalance = get_unconfirmed_balance(conn);
                        println!("Unconfirmed Balance: {} OMI", ubalance as f64 / 100000000.0);
                    } else {
                        println!("No wallet database available");
                    }
                }
                ["unspent_utxo"] => {
                    if let Some(ref conn) = conn {
                        match get_unspent_utxos(conn) {
                            Ok(utxos) => {
                                if utxos.is_empty() {
                                    println!("\nNo unspent transaction outputs found");
                                } else {
                                    println!("\nUnspent Transaction Outputs:");
                                    for utxo in utxos {
                                        println!(
                                            "TXID: {}, Vout: {}, Amount: {} OMI, Status: {}",
                                            utxo.txid,
                                            utxo.vout,
                                            utxo.amount as f64 / 100000000.0,
                                            utxo.status
                                        );
                                    }
                                }
                            }
                            Err(e) => println!("\nError fetching UTXOs: {}", e),
                        }
                    } else {
                        println!("\nNo wallet database available");
                    }
                }
                ["send", addresses @ ..] => {
                    if addresses.len() % 2 != 0 || addresses.is_empty() {
                        println!("\nInvalid send command. Usage: send <addr1> <amount1> [addr2 amount2 ...]");
                        continue;
                    }

                    if let Some(ref conn) = conn {
                        let mut dest_addresses = Vec::new();
                        let mut amounts = Vec::new();
                        let mut total_amount = 0u64;

                        for chunk in addresses.chunks(2) {
                            let address = chunk[0];
							
							if address.len() != 64 || address.chars().any(|c| !c.is_ascii_hexdigit()) {
								println!("\nInvalid address: {} (must be 64-character hex string)", address);
								continue;
							}
							
                            let amount_omi: f64 = match chunk[1].parse() {
                                Ok(amount) => amount,
                                Err(_) => {
                                    println!("\nInvalid amount: {}", chunk[1]);
                                    continue;
                                }
                            };
                            let amount = (amount_omi * 100000000.0).round() as u64;
                            
                            dest_addresses.push(address);
                            amounts.push(amount);
                            total_amount += amount;
                        }

                        if amounts.is_empty() {
                            println!("\nNo valid amounts provided");
                            continue;
                        }

                        match get_unspent_utxos(conn) {
                            Ok(utxos) => {
                                let fee_per_input = 5000;
                                let fee_per_output = 2000;
                                
                                let output_count = dest_addresses.len() + 1;
                                let mut fee_estimate = fee_per_input + (output_count as u64 * fee_per_output);
                                
                                let (selected_utxos, total_inputs, actual_fee) = select_utxos(&utxos, total_amount, fee_per_input);
                                
                                if selected_utxos.is_empty() {
                                    println!("\nNot enough funds or no UTXOs available");
                                    continue;
                                }
								
                                let exact_fee = (selected_utxos.len() as u64 * fee_per_input) + (output_count as u64 * fee_per_output);
                                
                                if total_inputs < total_amount + exact_fee {
                                    println!("\nNot enough funds when including exact fees");
                                    println!("- Needed: {} (amount) + {} (fees) = {}", 
                                        total_amount, exact_fee, total_amount + exact_fee);
                                    println!("- Available: {}", total_inputs);
                                    continue;
                                }

                                let (inputs, outputs, fee) = build_transaction(
                                    &selected_utxos,
                                    amounts,
                                    exact_fee,
                                    dest_addresses,
                                    &address,
                                );

                                println!("\nOutputs:");
                                for output in &outputs {
                                    println!("- {} -> {} OMI", 
                                        output.0, output.1 as f64 / 100000000.0);
                                }

                                println!("\nFee: {} OMI ({} inputs × {} + {} outputs × {})", 
                                    fee as f64 / 100000000.0,
                                    selected_utxos.len(), fee_per_input,
                                    output_count, fee_per_output);

                                let mut raw_tx = RawTransaction {
                                    inputcount: format!("{:02x}", inputs.len()),
                                    inputs: inputs.iter().map(|(txid, vout, _)| {
                                        INTXO {
                                            txid: txid.clone(),
                                            vout: *vout,
                                            extrasize: "00".to_string(),
                                            extra: "".to_string(),
                                            sequence: 0xFFFFFFFF,
                                        }
                                    }).collect(),
                                    outputcount: format!("{:02x}", outputs.len()),
                                    outputs: outputs.clone(),
                                    fee: exact_fee,
                                    sigpub: encode(pk.as_bytes()),
                                    signature: "".to_string(),
                                };
                                let tx_binary = bincode::serialize(&raw_tx)
                                    .expect("Failed to serialize transaction");
                                let tx_hash = blake3::hash(&tx_binary);
                                let signature = detached_sign(tx_hash.as_bytes(), &sk);
                                let signature_hex = encode(signature.as_bytes());
                                raw_tx.signature = signature_hex;
                                let signed_tx_binary = bincode::serialize(&raw_tx)
                                    .expect("Failed to serialize signed transaction");
                                let signed_tx_hex = encode(&signed_tx_binary);
                                println!("\nTransaction signed successfully");
                                println!("Transaction ID: {}", encode(tx_hash.as_bytes()));
                                println!("\nBroadcasting transaction...");

                                let send_request = json!({
                                    "jsonrpc": "2.0",
                                    "id": "pokio_wallet",
                                    "method": "pokio_sendRawTransaction",
                                    "params": [signed_tx_hex]
                                });
                                match client.post("http://localhost:40404/rpc")
                                    .header(header::CONTENT_TYPE, "application/json")
                                    .json(&send_request)
                                    .send() {
                                        Ok(resp) => {
                                            if let Ok(response_text) = resp.text() {
                                                println!("\nTransaction sent successfully");
                                                for (txid, vout, _) in inputs {
                                                    conn.execute(
                                                        "UPDATE inputs SET status = 'spent' WHERE txid = ?1 AND vout = ?2",
                                                        params![txid, vout],
                                                    ).expect("Failed to update input status");
                                                }
                                            }
                                        },
                                        Err(e) => println!("\nError sending transaction: {}", e),
                                    }
                            }
                            Err(e) => println!("\nError fetching UTXOs: {}", e),
                        }
                    } else {
                        println!("\nNo wallet database available");
                    }
                }
                _ => println!("\nUnknown command. Type 'help' for available commands."),
            }
        }

        if let Some(ref conn) = conn {
            if last_block % 10 == 1 {
                check_confirm_utxos(conn, &client);
            }
        }
		
		if let Some(ref conn) = conn {
            if last_block % 10 == 4 {
                check_confirm_utxos(conn, &client);
            }
        }
		
		if let Some(ref conn) = conn {
            if last_block % 10 == 8 {
                check_confirm_utxos(conn, &client);
            }
        }

        let request = json!({
            "jsonrpc": "2.0",
            "id": "pokio_wallet",
            "method": "pokio_getBlocks",
            "params": [last_block.to_string()]
        });
        let response = client.post("http://localhost:40404/rpc")
            .header(header::CONTENT_TYPE, "application/json")
            .json(&request)
            .send();
        match response {
            Ok(resp) => {
                let response_text = match resp.text() {
                    Ok(text) => text,
                    Err(_) => continue,
                };
                
                let json_response: Value = match serde_json::from_str(&response_text) {
                    Ok(json) => json,
                    Err(_) => continue,
                };
                
				
				
                if let Some(result) = json_response.get("result") {
                    if let Some(blocks) = result.as_array() {
                        if blocks.is_empty() {
                            std::thread::sleep(std::time::Duration::from_secs(5));
                            continue;
                        }
                        
                        for block in blocks {
                            if let Ok(block) = serde_json::from_value::<Block>(block.clone()) {
                                for tx_hex in block.transactions.split('-') {
                                    if let Ok(tx_bytes) = hex::decode(tx_hex.trim()) {
                                        if let Ok(raw_tx) = bincode::deserialize::<RawTransaction>(&tx_bytes) {

                                            for (vout, (output_address, amount)) in raw_tx.outputs.iter().enumerate() {
                                                if output_address == &address {
                                                    let b3_tx_hash = blake3::hash(tx_hex.as_bytes());
                                                    let tx_hash = hex::encode(b3_tx_hash.as_bytes());

                                                    println!("{}: {} OMI", tx_hash, *amount as f64 / 100000000.0);

                                                    if let Some(ref conn) = conn {
                                                        insert_input(
                                                            conn, 
                                                            &tx_hash, 
                                                            vout as u32, 
                                                            *amount, 
                                                            "unconfirmed",
                                                            Some(&block.hash),
                                                            Some(block.height),
                                                        );
                                                        let balance = get_balance(conn);
                                                        //println!("Updated balance: {} OMI", balance as f64 / 100000000.0);
                                                    }
                                                }
                                            }

                                            for input in &raw_tx.inputs {
                                                if let Some(ref conn) = conn {
                                                    let _ = conn.execute(
                                                        "UPDATE inputs SET status = 'spent' WHERE txid = ?1 AND vout = ?2",
                                                        params![input.txid, input.vout],
                                                    );
                                                }
                                            }
                                        }
                                    }
                                }
                                
                                if block.height >= last_block {
                                    last_block = block.height + 1;
                                    if let Some(ref conn) = conn {
                                        update_last_block(conn, last_block);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Err(_) => {
                std::thread::sleep(std::time::Duration::from_secs(5));
            }
        }

        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}