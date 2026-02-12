# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Himalaya is a CLI tool to manage emails, written in Rust. It supports multiple backends (IMAP, Maildir, Notmuch) and message sending protocols (SMTP, Sendmail), with optional OAuth 2.0 and PGP support via cargo features.

## Build Commands

### Standard build
```bash
cargo build
```

### Release build
```bash
cargo build --release
```

### Build with specific features
```bash
# Minimal IMAP-only build
cargo build --no-default-features --features imap

# Full-featured build
cargo build --no-default-features --features imap,smtp,keyring,oauth2,wizard,pgp-commands
```

Default features are defined in Cargo.toml line 19: `imap`, `maildir`, `smtp`, `sendmail`, `wizard`, `pgp-commands`

### Check without building
```bash
cargo check
cargo check --no-default-features --features imap,smtp
```

## Running Tests

This project does not currently have a comprehensive test suite in the repository. Testing is typically done manually by running the CLI.

## Running the Application

### Direct execution
```bash
cargo run
```

### With arguments
```bash
cargo run -- envelope list
cargo run -- message read <id>
cargo run -- --help
```

### Debugging
Use environment variables for detailed logging:
```bash
RUST_LOG=debug cargo run 2>/tmp/himalaya.log
RUST_LOG=trace RUST_BACKTRACE=1 cargo run
```

Or use CLI flags:
```bash
cargo run -- --debug envelope list
cargo run -- --trace message send
```

## Code Architecture

### Module Organization

The codebase follows a command-based architecture organized by email domain concepts:

- **src/cli.rs**: Entry point defining the CLI structure using `clap`. All commands are exposed through the `HimalayaCommand` enum.
- **src/main.rs**: Application entry point. Handles special case of `mailto:` URLs and delegates to the CLI parser.
- **src/config.rs**: Configuration type alias pointing to `pimalaya-tui` implementation. The actual config logic is in external dependencies.

### Core Domain Modules

Each domain module follows the pattern: `mod.rs` → `arg/` (CLI arguments) → `command/` (command implementations)

- **src/account/**: Account management (list, configure, sync)
- **src/folder/**: Folder/mailbox operations (list, create, delete, expunge)
- **src/email/**: Split into:
  - **envelope/**: Message metadata (list, sort, search)
    - **flag/**: Flag operations (add, set, remove)
  - **message/**: Full message content (read, write, send, reply, forward)
    - **template/**: Message composition templates
    - **attachment/**: Attachment handling (download)

### Key Architecture Patterns

1. **Backend Abstraction**: The CLI layer doesn't implement email protocols directly. It relies on `email-lib` (from pimalaya/core) which provides backend-agnostic interfaces for IMAP, Maildir, Notmuch, SMTP, and Sendmail.

2. **Feature-Gated Compilation**: Almost all functionality is feature-gated. When adding new features, check Cargo.toml lines 18-30 to ensure required features are enabled.

3. **Command Pattern**: Each command is a separate module with its own argument struct and `execute()` method that takes a `Printer` and `TomlConfig`.

4. **Printer Abstraction**: Output formatting (plain text tables vs JSON) is handled by the `Printer` trait from `pimalaya-tui`.

5. **Config Patching**: The project uses local git dependencies for development (see `[patch.crates-io]` section in Cargo.toml). When modifying dependencies, you may need to override paths as documented in CONTRIBUTING.md.

### External Dependencies Structure

Himalaya is part of the Pimalaya ecosystem:
- **email-lib**: Core email handling (backends, parsing, thread building)
- **mml-lib**: MIME Meta Language for message composition
- **pimalaya-tui**: TUI components, config parsing, printing
- **secret-lib**: Password and keyring management
- **Various protocol libs**: imap-client, imap-codec, etc.

## Development Workflow

### Environment Setup

Preferred: Use Nix shell (`nix-shell`) which provides all dependencies.

Alternative: Use rustup with Rust 1.82 (see rust-toolchain.toml).

### Dependency Overrides

To develop against local versions of pimalaya dependencies, add to Cargo.toml:

```toml
[patch.crates-io]
email-lib = { path = "/path/to/core/email" }
mml-lib = { path = "/path/to/core/mml" }
```

See CONTRIBUTING.md lines 37-63 for complete override examples.

### Commit Conventions

Follow conventional commits (type: description) as specified in CONTRIBUTING.md line 69.

## Configuration

Configuration is loaded from `~/.config/himalaya/config.toml` (or paths specified via `-c`/`--config` or `HIMALAYA_CONFIG`).

See `config.sample.toml` for comprehensive configuration examples including:
- Multi-account setup
- Backend configuration (IMAP, SMTP, Maildir, Notmuch)
- OAuth 2.0 setup for Gmail/Outlook
- PGP integration
- Folder aliases
- Display customization

## Important Notes

- The configuration logic is implemented in `pimalaya-tui`, not in this repository.
- When the CLI runs without arguments, it defaults to listing envelopes (see main.rs:38-43).
- The `mailto:` protocol is specially handled at startup (main.rs:21-32).
- Keyring integration requires the `keyring` feature and sets global service name to "himalaya-cli" (main.rs:17).
