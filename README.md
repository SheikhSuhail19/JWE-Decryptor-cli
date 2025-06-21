# 🔐 JWE Token Decryptor

A Python CLI tool to decrypt JWE (JSON Web Encryption) tokens using a symmetric key (base64url-encoded). Supports YAML-based configuration or interactive prompt-based input. It can also decode and pretty-print JWT claims from the decrypted token. Also includes a Java example for JWE encryption/decryption using RSA keys.

---

## 📦 Features

- Decrypt JWE tokens using a base64url-encoded symmetric key
- Accepts input via:

  - YAML configuration file
  - Interactive stdin prompt

- Optionally parse and pretty-print JWT claims (`--claims`)
- Verbose logging support (`--verbose`)

---

## 🛠️ Requirements

- Python 3.6 or higher
- Install dependencies using:

```bash
pip install -r requirements.txt
```

**requirements.txt**:

```
jwcrypto
pyyaml
```

---

## 🚀 Usage

### 🔧 Using a Config File

Create a `config.yaml` file like this:

```yaml
key: "base64url-encoded-key"
token: "full-encrypted-jwe-token"
```

Run the script:

```bash
python3 jwe_decrypt.py -c config.yaml
```

### 🧑‍💻 Interactive Prompt (No Config)

If no config file is provided, the script prompts for input:

```bash
python3 jwe_decrypt.py
```

You will be asked to:

- Enter the symmetric key
- Paste the JWE token (terminate with Ctrl+D or Enter twice)

---

## 🧾 Output Modes

### Basic Decryption

```bash
python3 jwe_decrypt.py -c config.yaml
```

### Decryption + JWT Claim Parsing

```bash
python3 jwe_decrypt.py -c config.yaml --claims
```

### Enable Debug Logs

```bash
python3 jwe_decrypt.py -c config.yaml --verbose
```

### Combine Options

```bash
python3 jwe_decrypt.py -c config.yaml --claims --verbose
```

---

## 🔍 Example Output

```
[INFO] ✅ Decryption successful!
[INFO] 🪪 Decrypted JWT Token:
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

[INFO] 🔍 JWT Header:
{
  "alg": "HS256",
  "typ": "JWT"
}

[INFO] 📜 JWT Claims:
{
  "sub": "user@example.com",
  "exp": 9999999999
}
```

---

## 🧯 Troubleshooting

- **Invalid key/token**: Ensure both are base64url-encoded and not truncated
- **Key mismatch**: Decryption will fail if the key doesn't match the token
- **Malformed JWT**: You may see parsing errors if the decrypted token isn't a valid JWT

---

## 🧙 Author

**Suhail** — Software Engineer, Token whisperer, Bullshit remover.

---

## 🪦 License

MIT — Do whatever, just don’t blame me if your secrets leak.

---
