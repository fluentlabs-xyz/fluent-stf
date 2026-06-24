use alloy_genesis::{ChainConfig, Genesis, GenesisAccount};
use alloy_primitives::{Address, Bytes, U256};
use reth_chainspec::{
    make_genesis_header, ChainHardforks, EthereumHardfork, ForkCondition, Hardfork,
};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    str::FromStr,
};

pub const FLUENT_DEVNET_CHAIN_ID: u64 = 0x5201;
pub const FLUENT_TESTNET_CHAIN_ID: u64 = 0x5202;
pub const FLUENT_MAINNET_CHAIN_ID: u64 = 25363;

// ─── network definitions ────────────────────────────────────────────────────

struct NetworkDef {
    /// Cargo feature name (e.g. "mainnet", "testnet", "devnet").
    feature: &'static str,
    /// GitHub release tag
    tag: &'static str,
    /// Optional channel for the download URL
    channel: Option<&'static str>,
    /// Osaka hardfork condition
    osaka_fork: ForkCondition,
    /// Override the chain ID for this network
    chain_id: u64,
}

/// All supported networks.
fn network_defs() -> Vec<NetworkDef> {
    vec![
        NetworkDef {
            feature: "mainnet",
            tag: "v1.0.0", // FLUENT_MAINNET_GENESIS_TAG
            channel: Some("mainnet"),
            osaka_fork: ForkCondition::Timestamp(0),
            chain_id: FLUENT_MAINNET_CHAIN_ID,
        },
        NetworkDef {
            feature: "testnet",
            tag: "v0.3.4-dev", // FLUENT_TESTNET_GENESIS_TAG
            channel: None,
            osaka_fork: ForkCondition::Block(21_300_000),
            chain_id: FLUENT_TESTNET_CHAIN_ID,
        },
        NetworkDef {
            feature: "devnet",
            tag: "v0.5.7", // FLUENT_DEVNET_GENESIS_TAG
            channel: None,
            osaka_fork: ForkCondition::Block(0),
            chain_id: FLUENT_DEVNET_CHAIN_ID,
        },
    ]
}

// ─── genesis download & cache ───────────────────────────────────────────────

fn genesis_cache_dir() -> PathBuf {
    if let Some(proj) = directories::ProjectDirs::from("xyz", "fluentlabs", "fluent") {
        proj.cache_dir().join("genesis")
    } else {
        PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("genesis_cache")
    }
}

pub fn genesis_urls(tag: &str, channel: Option<&str>) -> (String, String) {
    let base = format!("https://github.com/fluentlabs-xyz/fluentbase/releases/download/{tag}");
    let gz_name = if let Some(channel) = channel {
        format!("genesis-{channel}-{tag}.json.gz")
    } else {
        format!("genesis-{tag}.json.gz")
    };
    let gz_url = format!("{base}/{gz_name}");
    (gz_url, gz_name)
}

fn download_to(url: &str, path: &Path) {
    let tmp = path.with_extension("tmp");
    let resp = reqwest::blocking::Client::builder()
        .user_agent("fluent-chainspec-build/1.0")
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .unwrap()
        .get(url)
        .send()
        .unwrap()
        .error_for_status()
        .unwrap();

    let bytes = resp.bytes().unwrap();
    let mut f = fs::File::create(&tmp).unwrap();
    f.write_all(&bytes).unwrap();
    f.sync_all().unwrap();
    fs::rename(&tmp, path).unwrap();
}

fn download_and_cache_genesis(tag: &str, channel: Option<&str>) -> (Value, PathBuf) {
    let (gz_url, gz_name) = genesis_urls(tag, channel);
    let cache_dir = genesis_cache_dir();
    fs::create_dir_all(&cache_dir).unwrap();
    let gz_path = cache_dir.join(&gz_name);

    if !gz_path.exists() {
        println!("cargo:warning=Downloading genesis from {gz_url}...");
        download_to(&gz_url, &gz_path);
    } else {
        println!("cargo:warning=Using cached genesis from {}", gz_path.display());
    }

    let gz_bytes = fs::read(&gz_path).unwrap();
    let mut decoder = flate2::read::GzDecoder::new(&gz_bytes[..]);
    let mut json_str = String::new();
    decoder.read_to_string(&mut json_str).unwrap();
    let val = serde_json::from_str(&json_str).unwrap();

    (val, gz_path)
}

// ─── formatting helpers ─────────────────────────────────────────────────────

fn write_if_changed(path: &Path, content: &[u8]) {
    if let Ok(existing) = fs::read(path) {
        if existing == content {
            return;
        }
    }
    fs::write(path, content).unwrap();
}

fn write_bin_if_changed(path: &Path, bytes: &[u8]) {
    if let Ok(existing) = fs::read(path) {
        if existing == bytes {
            return;
        }
    }
    fs::write(path, bytes).unwrap();
}

fn fmt_b256(val: &alloy_primitives::B256) -> String {
    format!("b256!(\"{}\")", hex::encode(val.as_slice()))
}
fn fmt_opt_b256(val: &Option<alloy_primitives::B256>) -> String {
    match val {
        Some(v) => format!("Some({})", fmt_b256(v)),
        None => "None".to_string(),
    }
}
fn fmt_opt_u64(val: Option<u64>) -> String {
    match val {
        Some(v) => format!("Some({v}u64)"),
        None => "None".to_string(),
    }
}
fn fmt_u256(val: &U256) -> String {
    if val.is_zero() {
        return "U256::ZERO".to_string();
    }
    let bytes = val.to_be_bytes::<32>();
    format!(
        "U256::from_be_bytes([{}])",
        bytes.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(",")
    )
}
fn fmt_bloom(bloom: &alloy_primitives::Bloom) -> String {
    if bloom.is_zero() {
        "Bloom::ZERO".to_string()
    } else {
        format!(
            "Bloom::new([{}])",
            bloom.as_slice().iter().map(|b| b.to_string()).collect::<Vec<_>>().join(",")
        )
    }
}
fn fmt_bytes(bytes: &Bytes) -> String {
    if bytes.is_empty() {
        "Bytes::default()".to_string()
    } else {
        format!(
            "Bytes::from_static(&[{}])",
            bytes.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(",")
        )
    }
}
fn parse_json_u64(val: &Value) -> u64 {
    if let Some(num) = val.as_u64() {
        return num;
    }
    if let Some(s) = val.as_str() {
        return u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap_or(0);
    }
    0
}
fn canonical_addr(raw: &str) -> String {
    format!("{:0>40}", raw.trim_start_matches("0x").to_lowercase())
}

// ─── account codegen ────────────────────────────────────────────────────────

fn emit_account(network: &str, addr_clean: &str, account: &Value, bin_dir: &Path) -> String {
    let balance_hex = account["balance"].as_str().unwrap_or("0x0");
    let balance_lit = fmt_u256(&U256::from_str(balance_hex).unwrap_or_default());
    let nonce_val = parse_json_u64(&account["nonce"]);
    let nonce_lit =
        if nonce_val > 0 { format!("Some({nonce_val}u64)") } else { "None".to_string() };

    let fname = format!("code_{network}_{addr_clean}.bin");
    let code_lit = match account["code"].as_str() {
        Some(code_hex) => {
            let bytes = Bytes::from_str(code_hex).unwrap_or_default();
            if bytes.is_empty() {
                "None".to_string()
            } else {
                write_bin_if_changed(&bin_dir.join(&fname), &bytes);
                format!(
                    r#"Some(Bytes::from_static(include_bytes!(concat!(env!("OUT_DIR"), "/fluent_genesis_bin/{fname}"))))"#
                )
            }
        }
        None => "None".to_string(),
    };

    format!(
        r#"(address!("{addr_clean}"), GenesisAccount {{ balance: {balance_lit}, code: {code_lit}, nonce: {nonce_lit}, storage: None, private_key: None }})"#
    )
}

// ─── build Genesis object from JSON ─────────────────────────────────────────

fn build_genesis_object(json: &Value, chain_id: u64) -> Genesis {
    let mut alloc = BTreeMap::new();
    if let Some(alloc_obj) = json["alloc"].as_object() {
        for (addr, account) in alloc_obj {
            let addr_clean = canonical_addr(addr);
            let address: Address = addr_clean.parse().unwrap();
            let balance =
                U256::from_str(account["balance"].as_str().unwrap_or("0x0")).unwrap_or_default();
            let nonce_val = parse_json_u64(&account["nonce"]);
            let nonce = if nonce_val > 0 { Some(nonce_val) } else { None };
            let code = account["code"].as_str().and_then(|c| {
                let b = Bytes::from_str(c).unwrap_or_default();
                if b.is_empty() {
                    None
                } else {
                    Some(b)
                }
            });
            alloc.insert(
                address,
                GenesisAccount { balance, code, nonce, storage: None, private_key: None },
            );
        }
    }

    let cfg = &json["config"];
    let config = ChainConfig {
        chain_id,
        homestead_block: cfg["homesteadBlock"].as_u64(),
        dao_fork_block: cfg["daoForkBlock"].as_u64(),
        dao_fork_support: cfg["daoForkSupport"].as_bool().unwrap_or(false),
        eip150_block: cfg["eip150Block"].as_u64(),
        eip155_block: cfg["eip155Block"].as_u64(),
        eip158_block: cfg["eip158Block"].as_u64(),
        byzantium_block: cfg["byzantiumBlock"].as_u64(),
        constantinople_block: cfg["constantinopleBlock"].as_u64(),
        petersburg_block: cfg["petersburgBlock"].as_u64(),
        istanbul_block: cfg["istanbulBlock"].as_u64(),
        muir_glacier_block: cfg["muirGlacierBlock"].as_u64(),
        berlin_block: cfg["berlinBlock"].as_u64(),
        london_block: cfg["londonBlock"].as_u64(),
        arrow_glacier_block: cfg["arrowGlacierBlock"].as_u64(),
        gray_glacier_block: cfg["grayGlacierBlock"].as_u64(),
        merge_netsplit_block: cfg["mergeNetsplitBlock"].as_u64(),
        shanghai_time: cfg["shanghaiTime"].as_u64(),
        cancun_time: cfg["cancunTime"].as_u64(),
        prague_time: cfg["pragueTime"].as_u64(),
        osaka_time: cfg["osakaTime"].as_u64().or(Some(999999999999)),
        terminal_total_difficulty_passed: cfg["terminalTotalDifficultyPassed"]
            .as_bool()
            .unwrap_or(false),
        ..Default::default()
    };

    let difficulty =
        U256::from_str(json["difficulty"].as_str().unwrap_or("0x0")).unwrap_or_default();
    let mix_hash_str =
        format!("{:0>64}", json["mixHash"].as_str().unwrap_or("0x0").trim_start_matches("0x"));
    let coinbase_str =
        format!("{:0>40}", json["coinbase"].as_str().unwrap_or("0x0").trim_start_matches("0x"));
    let extra_data =
        Bytes::from_str(json["extraData"].as_str().unwrap_or("0x")).unwrap_or_default();

    Genesis {
        config,
        nonce: parse_json_u64(&json["nonce"]),
        timestamp: parse_json_u64(&json["timestamp"]),
        gas_limit: parse_json_u64(&json["gasLimit"]),
        number: Some(parse_json_u64(&json["number"])),
        difficulty,
        mix_hash: mix_hash_str.parse().unwrap_or_default(),
        coinbase: coinbase_str.parse().unwrap_or_default(),
        extra_data,
        alloc,
        ..Default::default()
    }
}

// ─── codegen: emit one network block ────────────────────────────────────────

fn emit_network(
    out: &mut String,
    bin_dir: &Path,
    json: &Value,
    genesis_obj: &Genesis,
    hardforks: &ChainHardforks,
    net_def: &NetworkDef,
) {
    let header = make_genesis_header(genesis_obj, hardforks);
    let alloc_map: BTreeMap<String, Value> = json["alloc"]
        .as_object()
        .map(|obj| obj.iter().map(|(a, v)| (canonical_addr(a), v.clone())).collect())
        .unwrap_or_default();
    let count = alloc_map.len();

    let feat = net_def.feature;
    let cfg_attr = format!("#[cfg(feature = \"{feat}\")]");
    let mod_name = feat;

    out.push_str(&format!("{cfg_attr}\n"));
    out.push_str(&format!("mod {mod_name}_genesis {{\n    use super::*;\n\n"));

    out.push_str(&format!("    pub const ALLOC_LEN: usize = {count};\n\n"));
    out.push_str(
        "    pub fn genesis_alloc() -> [(Address, GenesisAccount); ALLOC_LEN] {\n        [\n",
    );
    for (addr_clean, account) in &alloc_map {
        out.push_str(&format!(
            "            {},\n",
            emit_account(net_def.feature, addr_clean, account, bin_dir)
        ));
    }
    out.push_str("        ]\n    }\n\n");

    out.push_str("    pub fn genesis() -> Genesis {\n");
    out.push_str("        let alloc: BTreeMap<Address, GenesisAccount> = genesis_alloc().into_iter().collect();\n\n");
    emit_chain_config(out, &genesis_obj.config);
    emit_genesis_struct(out, genesis_obj);
    out.push_str("    }\n\n");

    out.push_str("    pub fn genesis_header() -> Header {\n        Header {\n");
    emit_header_fields(out, &header);
    out.push_str("        }\n    }\n\n");

    // ─── chainspec() ────────────────────────────────────────────────────────

    let osaka_fmt = match &net_def.osaka_fork {
        ForkCondition::Block(b) => format!("ForkCondition::Block({b})"),
        ForkCondition::Timestamp(t) => format!("ForkCondition::Timestamp({t})"),
        _ => "ForkCondition::Block(0)".to_string(),
    };

    out.push_str("    pub fn chainspec() -> ChainSpec {\n");
    out.push_str("        let gen = genesis();\n");
    out.push_str(&format!(
        "        let hardforks = fluent_default_chain_hardforks({});\n",
        osaka_fmt
    ));
    out.push_str("        ChainSpec {\n");
    out.push_str(&format!(
        "            chain: reth_chainspec::Chain::from({}u64),\n",
        genesis_obj.config.chain_id
    ));
    out.push_str("            genesis_header: SealedHeader::new_unhashed(genesis_header()),\n");
    out.push_str("            genesis: gen,\n");
    out.push_str("            paris_block_and_final_difficulty: Some((0, U256::ZERO)),\n");
    out.push_str("            hardforks,\n");
    out.push_str(
        "            base_fee_params: BaseFeeParamsKind::Constant(BaseFeeParams::ethereum()),\n",
    );
    out.push_str("            deposit_contract: None,\n");
    out.push_str("            ..Default::default()\n");
    out.push_str("        }\n");
    out.push_str("    }\n");

    out.push_str(&format!("}} // mod {mod_name}_genesis\n\n"));
    out.push_str(&format!("{cfg_attr}\n"));
    out.push_str(&format!("pub use {mod_name}_genesis::*;\n\n"));
}

fn emit_chain_config(out: &mut String, cfg: &ChainConfig) {
    out.push_str("        let config = ChainConfig {\n");
    out.push_str(&format!("            chain_id: {}u64,\n", cfg.chain_id));
    out.push_str(&format!("            homestead_block: {},\n", fmt_opt_u64(cfg.homestead_block)));
    out.push_str(&format!("            dao_fork_block: {},\n", fmt_opt_u64(cfg.dao_fork_block)));
    out.push_str(&format!("            dao_fork_support: {},\n", cfg.dao_fork_support));
    out.push_str(&format!("            eip150_block: {},\n", fmt_opt_u64(cfg.eip150_block)));
    out.push_str(&format!("            eip155_block: {},\n", fmt_opt_u64(cfg.eip155_block)));
    out.push_str(&format!("            eip158_block: {},\n", fmt_opt_u64(cfg.eip158_block)));
    out.push_str(&format!("            byzantium_block: {},\n", fmt_opt_u64(cfg.byzantium_block)));
    out.push_str(&format!(
        "            constantinople_block: {},\n",
        fmt_opt_u64(cfg.constantinople_block)
    ));
    out.push_str(&format!(
        "            petersburg_block: {},\n",
        fmt_opt_u64(cfg.petersburg_block)
    ));
    out.push_str(&format!("            istanbul_block: {},\n", fmt_opt_u64(cfg.istanbul_block)));
    out.push_str(&format!(
        "            muir_glacier_block: {},\n",
        fmt_opt_u64(cfg.muir_glacier_block)
    ));
    out.push_str(&format!("            berlin_block: {},\n", fmt_opt_u64(cfg.berlin_block)));
    out.push_str(&format!("            london_block: {},\n", fmt_opt_u64(cfg.london_block)));
    out.push_str(&format!(
        "            arrow_glacier_block: {},\n",
        fmt_opt_u64(cfg.arrow_glacier_block)
    ));
    out.push_str(&format!(
        "            gray_glacier_block: {},\n",
        fmt_opt_u64(cfg.gray_glacier_block)
    ));
    out.push_str(&format!(
        "            merge_netsplit_block: {},\n",
        fmt_opt_u64(cfg.merge_netsplit_block)
    ));
    out.push_str(&format!("            shanghai_time: {},\n", fmt_opt_u64(cfg.shanghai_time)));
    out.push_str(&format!("            cancun_time: {},\n", fmt_opt_u64(cfg.cancun_time)));
    out.push_str(&format!("            prague_time: {},\n", fmt_opt_u64(cfg.prague_time)));
    out.push_str(&format!("            osaka_time: {},\n", fmt_opt_u64(cfg.osaka_time)));
    out.push_str(&format!(
        "            terminal_total_difficulty_passed: {},\n",
        cfg.terminal_total_difficulty_passed
    ));
    out.push_str("            ..Default::default()\n");
    out.push_str("        };\n\n");
}

fn emit_genesis_struct(out: &mut String, g: &Genesis) {
    out.push_str("        Genesis {\n            config,\n");
    out.push_str(&format!("            nonce: {}u64,\n", g.nonce));
    out.push_str(&format!("            timestamp: {}u64,\n", g.timestamp));
    out.push_str(&format!("            gas_limit: {}u64,\n", g.gas_limit));
    out.push_str(&format!("            number: {},\n", fmt_opt_u64(g.number)));
    out.push_str(&format!("            difficulty: {},\n", fmt_u256(&g.difficulty)));
    out.push_str(&format!("            mix_hash: {},\n", fmt_b256(&g.mix_hash)));
    out.push_str(&format!(
        "            coinbase: address!(\"{}\"),\n",
        hex::encode(g.coinbase.as_slice())
    ));
    out.push_str(&format!("            extra_data: {},\n", fmt_bytes(&g.extra_data)));
    out.push_str("            alloc,\n            ..Default::default()\n        }\n");
}

fn emit_header_fields(out: &mut String, h: &alloy_consensus::Header) {
    out.push_str(&format!("            parent_hash: {},\n", fmt_b256(&h.parent_hash)));
    out.push_str(&format!("            ommers_hash: {},\n", fmt_b256(&h.ommers_hash)));
    out.push_str(&format!(
        "            beneficiary: address!(\"{}\"),\n",
        hex::encode(h.beneficiary.as_slice())
    ));
    out.push_str(&format!("            state_root: {},\n", fmt_b256(&h.state_root)));
    out.push_str(&format!("            transactions_root: {},\n", fmt_b256(&h.transactions_root)));
    out.push_str(&format!("            receipts_root: {},\n", fmt_b256(&h.receipts_root)));
    out.push_str(&format!("            logs_bloom: {},\n", fmt_bloom(&h.logs_bloom)));
    out.push_str(&format!("            difficulty: {},\n", fmt_u256(&h.difficulty)));
    out.push_str(&format!("            number: {}u64,\n", h.number));
    out.push_str(&format!("            gas_limit: {}u64,\n", h.gas_limit));
    out.push_str(&format!("            gas_used: {}u64,\n", h.gas_used));
    out.push_str(&format!("            timestamp: {}u64,\n", h.timestamp));
    out.push_str(&format!("            extra_data: {},\n", fmt_bytes(&h.extra_data)));
    out.push_str(&format!("            mix_hash: {},\n", fmt_b256(&h.mix_hash)));
    out.push_str(&format!(
        "            nonce: 0x{:016x}u64.into(),\n",
        u64::from_be_bytes(h.nonce.0)
    ));
    out.push_str(&format!("            base_fee_per_gas: {},\n", fmt_opt_u64(h.base_fee_per_gas)));
    out.push_str(&format!(
        "            withdrawals_root: {},\n",
        fmt_opt_b256(&h.withdrawals_root)
    ));
    out.push_str(&format!("            blob_gas_used: {},\n", fmt_opt_u64(h.blob_gas_used)));
    out.push_str(&format!("            excess_blob_gas: {},\n", fmt_opt_u64(h.excess_blob_gas)));
    out.push_str(&format!(
        "            parent_beacon_block_root: {},\n",
        fmt_opt_b256(&h.parent_beacon_block_root)
    ));
    out.push_str(&format!("            requests_hash: {},\n", fmt_opt_b256(&h.requests_hash)));
    out.push_str("            block_access_list_hash: None,\n");
    out.push_str("            slot_number: None,\n");
}

// ─── hardforks helper for build step ─────────────────────────────────────────

fn fluent_default_chain_hardforks(osaka_fork: ForkCondition) -> ChainHardforks {
    ChainHardforks::new(vec![
        (EthereumHardfork::Frontier.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Homestead.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Dao.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Tangerine.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::SpuriousDragon.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Byzantium.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Constantinople.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Petersburg.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Istanbul.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Berlin.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::London.boxed(), ForkCondition::Block(0)),
        (
            EthereumHardfork::Paris.boxed(),
            ForkCondition::TTD {
                activation_block_number: 0,
                fork_block: None,
                total_difficulty: U256::ZERO,
            },
        ),
        (EthereumHardfork::Shanghai.boxed(), ForkCondition::Timestamp(0)),
        (EthereumHardfork::Cancun.boxed(), ForkCondition::Timestamp(0)),
        (EthereumHardfork::Prague.boxed(), ForkCondition::Timestamp(0)),
        (EthereumHardfork::Osaka.boxed(), osaka_fork),
    ])
}

// ─── main ───────────────────────────────────────────────────────────────────

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let bin_dir = out_dir.join("fluent_genesis_bin");
    fs::create_dir_all(&bin_dir).unwrap();

    let networks = network_defs();

    let mut out = String::new();
    out.push_str("// @generated — do not edit manually\n");

    out.push_str("use alloy_primitives::{address, b256, U256, Bytes, Address, Bloom};\n");
    out.push_str("use alloy_genesis::{Genesis, GenesisAccount, ChainConfig};\n");
    out.push_str("use reth_primitives_traits::Header;\n");
    out.push_str("use reth_chainspec::{ChainSpec, ChainHardforks, EthereumHardfork, ForkCondition, BaseFeeParamsKind, BaseFeeParams, Hardfork};\n");
    out.push_str("use reth_primitives_traits::SealedHeader;\n");
    out.push_str("use std::collections::BTreeMap;\n\n");

    out.push_str(
        r#"
pub fn fluent_default_chain_hardforks(osaka_fork: ForkCondition) -> ChainHardforks {
    ChainHardforks::new(vec![
        (EthereumHardfork::Frontier.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Homestead.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Dao.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Tangerine.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::SpuriousDragon.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Byzantium.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Constantinople.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Petersburg.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Istanbul.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Berlin.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::London.boxed(), ForkCondition::Block(0)),
        (
            EthereumHardfork::Paris.boxed(),
            ForkCondition::TTD {
                activation_block_number: 0,
                fork_block: None,
                total_difficulty: U256::ZERO,
            },
        ),
        (EthereumHardfork::Shanghai.boxed(), ForkCondition::Timestamp(0)),
        (EthereumHardfork::Cancun.boxed(), ForkCondition::Timestamp(0)),
        (EthereumHardfork::Prague.boxed(), ForkCondition::Timestamp(0)),
        (EthereumHardfork::Osaka.boxed(), osaka_fork),
    ])
}
"#,
    );

    let mut referenced_bins: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

    for net in &networks {
        let label = net.feature;
        println!("cargo:warning=Processing genesis for network: {label}");

        let (json, gz_path) = download_and_cache_genesis(net.tag, net.channel);
        println!("cargo:rerun-if-changed={}", gz_path.display());

        let genesis_obj = build_genesis_object(&json, net.chain_id);
        let hardforks = fluent_default_chain_hardforks(net.osaka_fork);

        // Mainnet integrity assertion: freeze the expected genesis identity so any
        // accidental change to the downloaded blob is caught at build time.
        if net.feature == "mainnet" {
            let header = make_genesis_header(&genesis_obj, &hardforks);
            assert_eq!(
                header.timestamp, 0x69b8194c,
                "fluent mainnet genesis timestamp mismatch (expected 0x69b8194c, got {:#x})",
                header.timestamp
            );
            let sealed = reth_primitives_traits::SealedHeader::seal_slow(header);
            let expected_hash = alloy_primitives::b256!(
                "0x7dd092d6e2aba158839db2a264d8049e7518540b342929822aac85f550c18465"
            );
            assert_eq!(
                sealed.hash(),
                expected_hash,
                "fluent mainnet genesis hash mismatch (expected {expected_hash}, got {})",
                sealed.hash()
            );
        }

        // Track which code_*.bin files this run references so we can purge stale ones.
        if let Some(alloc_obj) = json["alloc"].as_object() {
            for (addr, account) in alloc_obj {
                if let Some(code_hex) = account["code"].as_str() {
                    let bytes = Bytes::from_str(code_hex).unwrap_or_default();
                    if !bytes.is_empty() {
                        referenced_bins.insert(format!(
                            "code_{}_{}.bin",
                            net.feature,
                            canonical_addr(addr)
                        ));
                    }
                }
            }
        }

        emit_network(&mut out, &bin_dir, &json, &genesis_obj, &hardforks, net);
    }

    // Orphan-blob cleanup: drop any .bin under fluent_genesis_bin/ no longer referenced.
    if let Ok(entries) = fs::read_dir(&bin_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.ends_with(".bin") && !referenced_bins.contains(&name) {
                let _ = fs::remove_file(entry.path());
            }
        }
    }

    write_if_changed(&out_dir.join("fluent_genesis.rs"), out.as_bytes());
}
