# Installing Himalaya Security in Himalaya CLI

This guide explains how to integrate the security middleware into your Himalaya installation.

## Current Status

✅ **The library is installable** as a Cargo dependency
⚠️  **Email-lib integration pending** - trait implementations need to be completed

## Quick Install (Testing)

The easiest way to test the security features is to use the library directly in a standalone fashion:

### 1. Add as a path dependency

In your `Cargo.toml`:

```toml
[dependencies]
himalaya-security = { path = "himalaya-security" }

[features]
security = ["himalaya-security"]
```

**This has already been done!** Check `/home/dan/Code/himalaya/Cargo.toml` lines 31 and 43.

### 2. Use the library in your code

```rust
use himalaya_security::{Scanner, SecurityConfig};

// Scan email content
let config = SecurityConfig::default();
let scanner = Scanner::from_config(&config);
let result = scanner.scan_text(email_body, "message-id")?;

if !result.threats.is_empty() {
    println!("⚠️  Detected {} threats", result.threats.len());
}

// Process and sanitize
let safe_content = scanner.process_text(email_body, &result)?;
```

## Full Integration (Requires Email-lib Traits)

To fully integrate with Himalaya's backend system, we need to:

### Step 1: Enable email-lib dependency

Edit `himalaya-security/Cargo.toml`:

```toml
[dependencies]
# Uncomment this line:
email-lib = { version = "0.26", default-features = false, features = ["derive"] }
```

### Step 2: Implement email-lib traits

Add trait implementations in `src/middleware.rs`:

```rust
use email_lib::message::get::GetMessages;
use email_lib::message::peek::PeekMessages;

#[async_trait]
impl<T: GetMessages + Send + Sync> GetMessages for SecurityMiddleware<T> {
    async fn get_messages(
        &self,
        folder: &str,
        ids: &[&str],
    ) -> email_lib::Result<Messages> {
        // 1. Get messages from inner backend
        let messages = self.inner.get_messages(folder, ids).await?;

        // 2. Scan and process each message
        let mut processed = Vec::new();
        for msg in messages.iter() {
            let body = msg.get_body_text()?;  // Adjust based on actual API
            let sender = msg.get_sender();

            let safe_body = self.scan_and_process(
                msg.get_id(),
                &body,
                sender.as_deref()
            )?;

            // Create new message with sanitized content
            let mut safe_msg = msg.clone();
            safe_msg.set_body(safe_body)?;  // Adjust based on actual API
            processed.push(safe_msg);
        }

        Ok(Messages::from(processed))
    }
}

// Similar implementation for PeekMessages
```

### Step 3: Wire into Himalaya backend construction

Find where backends are constructed (likely in account setup) and wrap them:

```rust
#[cfg(feature = "security")]
use himalaya_security::{SecurityMiddleware, SecurityConfig};

// After constructing the IMAP backend:
let backend = if let Some(security_config) = config.security.as_ref() {
    // Wrap with security middleware
    let secure_backend = SecurityMiddleware::new(
        imap_backend.clone(),
        security_config.clone()
    );

    BackendBuilder::new()
        .set_get_messages(secure_backend.clone())
        .set_peek_messages(secure_backend)
        .set_list_envelopes(imap_backend.clone())  // No wrapping needed
        // ... other features
        .build()?
} else {
    // No security, use original
    BackendBuilder::new()
        .set_get_messages(imap_backend.clone())
        .set_peek_messages(imap_backend.clone())
        .build()?
};
```

### Step 4: Add security config to Himalaya's TOML config

Edit `~/.config/himalaya/config.toml`:

```toml
# Your existing config...

[security]
on-threat = "annotate"
pii-handling = "redact"
block-threshold = 0.8
# Optional: Load custom detection rules
# rules-path = "~/.config/himalaya/custom_rules.toml"

[security.scanners]
prompt-injection = true
pii-detection = true
```

### Step 5: Build with security feature

```bash
cargo build --features security
# or make it default in Cargo.toml features list
```

## Troubleshooting

### Edition2024 Error

If you encounter:
```
feature `edition2024` is required
```

This is due to dependencies (imap-codec) requiring Rust nightly. Solutions:

1. **Use Rust nightly temporarily**:
   ```bash
   rustup install nightly
   rustup override set nightly
   cargo build
   ```

2. **Wait for dependencies to update** - The pimalaya/core ecosystem is actively developed

3. **Use standalone mode** - The security library works independently without email-lib integration

### Test Security Features Standalone

You can test the security features without full Himalaya integration:

```bash
cd himalaya-security
cargo test
cargo run --example scan_email  # if we add examples
```

## Current Integration Status

**What works now:**
- ✅ Library compiles and all tests pass
- ✅ Can be added as Himalaya dependency
- ✅ Can use Scanner directly in Himalaya code
- ✅ TOML configuration ready

**What needs completion:**
- ⏳ Email-lib trait implementations (GetMessages, PeekMessages)
- ⏳ Backend wrapper integration points
- ⏳ Full MIME multipart support
- ⏳ Attachment scanning

## Next Steps

1. **Test standalone** - Use `Scanner` directly in Himalaya without full middleware
2. **Complete trait implementations** - Add GetMessages/PeekMessages impls
3. **Integration testing** - Test with real IMAP backends
4. **Submit upstream PR** - Propose security feature to pimalaya/himalaya

## Example: Manual Integration

For immediate use without waiting for full integration:

```rust
// In src/email/message/command/read.rs or similar
use himalaya_security::{Scanner, SecurityConfig};

pub async fn read_message(/* ... */) -> Result<()> {
    // ... existing code to get message ...

    #[cfg(feature = "security")]
    {
        let config = SecurityConfig::default();  // or load from user config
        let scanner = Scanner::from_config(&config);

        if let Ok(scan_result) = scanner.scan_text(&message_body, &message_id) {
            if !scan_result.threats.is_empty() {
                printer.print_warning(&format!(
                    "⚠️  Security: {} threats detected (risk: {:.0}%)",
                    scan_result.threats.len(),
                    scan_result.risk_score * 100.0
                ))?;
            }

            message_body = scanner.process_text(&message_body, &scan_result)
                .unwrap_or(message_body);
        }
    }

    // ... display message ...
}
```

This approach works **today** and provides immediate security benefits while full middleware integration is completed.
