//! Example showing how to load security configuration from TOML
//!
//! Run with: cargo run --example config_loading

use himalaya_security::SecurityConfig;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Security Configuration Loading Example ===\n");

    // Example 1: Load from default rules file
    println!("Example 1: Loading from default rules file");
    let default_config_path = "rules/default_rules.toml";

    if let Ok(content) = fs::read_to_string(default_config_path) {
        match toml::from_str::<SecurityConfig>(&content) {
            Ok(config) => {
                println!("✅ Loaded configuration:");
                println!("  Threat action: {:?}", config.on_threat);
                println!("  PII handling: {:?}", config.pii_handling);
                println!("  Block threshold: {}", config.block_threshold);
                println!("  Prompt injection enabled: {}", config.scanners.prompt_injection);
                println!("  PII detection enabled: {}", config.scanners.pii_detection);
                println!("  Allowlisted senders: {:?}", config.allowlisted_senders);
            }
            Err(e) => println!("❌ Parse error: {}", e),
        }
    } else {
        println!("⚠️  Default rules file not found (run from himalaya-security/ directory)");
    }

    // Example 2: Create config programmatically
    println!("\nExample 2: Creating configuration programmatically");
    let config = SecurityConfig {
        on_threat: himalaya_security::ThreatAction::Block,
        pii_handling: himalaya_security::PiiAction::Redact,
        block_threshold: 0.9,
        allowlisted_senders: vec![
            "noreply@github.com".to_string(),
            "notifications@slack.com".to_string(),
        ],
        ..Default::default()
    };

    println!("✅ Created configuration:");
    println!("  Threat action: {:?}", config.on_threat);
    println!("  PII handling: {:?}", config.pii_handling);
    println!("  Block threshold: {}", config.block_threshold);

    // Serialize back to TOML
    let toml_output = toml::to_string_pretty(&config)?;
    println!("\nAs TOML:");
    println!("{}", toml_output);

    // Example 3: Different security profiles
    println!("\nExample 3: Different security profiles");

    let profiles = vec![
        ("Paranoid", SecurityConfig {
            on_threat: himalaya_security::ThreatAction::Block,
            pii_handling: himalaya_security::PiiAction::Redact,
            block_threshold: 0.5,
            ..Default::default()
        }),
        ("Balanced", SecurityConfig {
            on_threat: himalaya_security::ThreatAction::Annotate,
            pii_handling: himalaya_security::PiiAction::Redact,
            block_threshold: 0.8,
            ..Default::default()
        }),
        ("Permissive", SecurityConfig {
            on_threat: himalaya_security::ThreatAction::LogOnly,
            pii_handling: himalaya_security::PiiAction::LogOnly,
            block_threshold: 0.95,
            ..Default::default()
        }),
    ];

    for (name, profile) in profiles {
        println!("\n{}:", name);
        println!("  On threat: {:?}", profile.on_threat);
        println!("  PII handling: {:?}", profile.pii_handling);
        println!("  Block threshold: {}", profile.block_threshold);
    }

    // Example 4: Recommended Himalaya config.toml section
    println!("\n=== Recommended Himalaya config.toml section ===");
    println!(r#"
# Add to your ~/.config/himalaya/config.toml

[security]
on-threat = "annotate"        # "block", "annotate", "redact", or "log-only"
pii-handling = "redact"       # "redact", "mask", "log-only", or "disabled"
block-threshold = 0.8         # 0.0-1.0, higher = more strict

# Skip scanning for trusted senders
allowlisted-senders = [
    "noreply@github.com",
    "notifications@slack.com"
]

[security.scanners]
prompt-injection = true       # Detect prompt injection attempts
pii-detection = true          # Detect personally identifiable information
"#);

    println!("\n=== End of configuration examples ===");
    Ok(())
}
