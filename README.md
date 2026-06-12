# Local Encrypted Password Manager

This program is a secure, local-first password manager implemented in Python using the `pycryptodome` library. It mitigates the mental burden of remembering multiple intricate passwords by requiring only a single master username and password pair.

Designed with zero-knowledge principles, the application runs entirely locally, features no cloud sync or password recovery, and guarantees data confidentiality and integrity through cryptographic derivations.

---

## Technical Features & Cryptographic Architecture

Instead of managing a central authentication database or keeping keys stored on disk, the application enforces the following workflows:

### 1. File and Identity Isolation

* **Deterministic File Naming:** To determine if an account exists without storing a plaintext registry, the application takes the master username, computes its **SHA-256** hash, and uses the resulting hexadecimal digest as the local filename.
* **Presence Checking:** If the hashed filename exists in the current working directory, the application attempts to open and decrypt it. If it does not exist, a new standalone vault file is provisioned.

### 2. Key Derivation Framework

* **Dynamic Key Material:** Master symmetric encryption keys are never written to disk. They are generated dynamically in memory whenever a user authenticates.
* **Hardened Stretching:** The application processes the master password through the **scrypt** Key Derivation Function (KDF) using a fixed, embedded salt value.
* **Parameters:** It explicitly utilizes a $128\text{-bit}$ ($16\text{-byte}$) key output size coupled with safety parameters designed to deter brute-force attackers: $N = 2^{14}$, $r = 8$, and $p = 1$.

### 3. Authenticated Encryption Layer

* **Cipher Mode:** Data protection is handled via Advanced Encryption Standard operating in Galois/Counter Mode (**AES-GCM**). This ensures both **confidentiality** (preventing unauthorized reading) and **integrity** (detecting unauthorized modifications).
* **Serialization Structure:** On execution exit, plaintext secrets are structured, prepended with a unique validation magic string, and encrypted. The resulting payload—comprising the `nonce`, `header`, `ciphertext`, and authentication `tag`—is packaged as Base64-encoded strings within a JSON schema.

### 4. Decryption Validation

* **Decryption Verification:** True AES-GCM tag matching confirms whether the payload has been altered.
* **Password Validation Boundary:** Since different master passwords generate distinct encryption keys, the system reads the first line of decrypted text to find the dedicated validation token:
`101010101010101010102020202020202020202030303030303030303030`
If the token matches, the vault initializes. If it is absent or malformed, the application rejects the login attempt as an invalid master key entry.

---

## Dependencies & Setup

The tool is compatible with Python 3 environments containing the `pycryptodome` library.

Install the required library via `pip`:

```bash
pip install pycryptodome

```

---

## Storage & Plaintext Format

When working in-memory, the records are represented as individual lines split into a strict colon-delimited format:

```text
username:password:domain
```

*IMPORTANT: Usernames, randomly generated passwords, and domain names must not contain a colon (`:`) character.*

---

## Usage

### Running the Application

Execute the script using Python:

```bash
python3 password_manager.py
```

### Menu Actions

Upon providing a master username and password, you interact with the vault using an interactive terminal menu:

1. **Add password:** Manually store a known username, password, and domain name combination.
2. **Create password:** Automatically generate a mathematically secure, random $16\text{-character}$ alphanumeric password (`[A-Za-z0-9]`) for a targeted domain.
3. **Update password:** Overwrite an existing domain entry with a freshly randomized $16\text{-character}$ password.
4. **Lookup password:** Query a domain name to reveal its associated password in cleartext.
5. **Delete password:** Remove a specific domain entry from the current vault loop.
6. **Display Vault:** Print the raw structural array of currently loaded records.
7. **Save Vault and Quit:** Package the list structure, prepend the magic verification header, encrypt the combined payload using AES-GCM, update the local disk file, and exit safely.
