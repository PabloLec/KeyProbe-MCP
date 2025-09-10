#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="${1:-tests/fixtures}"
umask 077

P12_PASS="changeit"
JKS_PASS="changeit"
PKCS8_PASS="secret"
SSH_PASS="secret"

# Create output directories
mkdir -p "$OUT_DIR"/{pem,der,pkcs7,pkcs12,pkcs8,openssh,jks,misc}

# Generate a self-signed root CA (RSA)
openssl req -x509 -newkey rsa:2048 -sha256 -days 730 -nodes \
  -subj "/CN=KeyProbe Test Root/O=KeyProbe Test/C=FR" \
  -keyout "$OUT_DIR/pem/root.key.pem" \
  -out "$OUT_DIR/pem/root.cert.pem"

# Generate leaf key and CSR (RSA)
openssl req -newkey rsa:2048 -nodes -sha256 \
  -subj "/CN=leaf.example.com/O=KeyProbe Test/C=FR" \
  -keyout "$OUT_DIR/pem/leaf.key.pem" \
  -out "$OUT_DIR/pem/leaf.csr.pem"

# Temporary SAN configuration for the leaf certificate
SAN_CFG="$(mktemp)"
cat >"$SAN_CFG" <<EOF
basicConstraints=CA:FALSE
subjectAltName=DNS:leaf.example.com,IP:127.0.0.1
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,clientAuth
EOF

# Sign the leaf CSR with the root CA
openssl x509 -req -in "$OUT_DIR/pem/leaf.csr.pem" \
  -CA "$OUT_DIR/pem/root.cert.pem" -CAkey "$OUT_DIR/pem/root.key.pem" -CAcreateserial \
  -out "$OUT_DIR/pem/leaf.cert.pem" -days 365 -sha256 -extfile "$SAN_CFG"

rm -f "$SAN_CFG" "$OUT_DIR/pem/root.cert.srl" || true

# Build a PEM chain (leaf + root)
cat "$OUT_DIR/pem/leaf.cert.pem" "$OUT_DIR/pem/root.cert.pem" > "$OUT_DIR/pem/chain.pem"

# Export the leaf certificate as DER
openssl x509 -in "$OUT_DIR/pem/leaf.cert.pem" -outform DER -out "$OUT_DIR/der/leaf.cert.der"

# Create PKCS#7 chains
# DER output
openssl crl2pkcs7 -nocrl \
  -certfile "$OUT_DIR/pem/leaf.cert.pem" -certfile "$OUT_DIR/pem/root.cert.pem" \
  -out "$OUT_DIR/pkcs7/chain.p7b" -outform DER
# PEM output
openssl crl2pkcs7 -nocrl \
  -certfile "$OUT_DIR/pem/chain.pem" \
  -out "$OUT_DIR/pkcs7/chain.pem.p7b"

# Create a PKCS#12 keystore (leaf key + cert + root)
openssl pkcs12 -export -name "leaf" \
  -inkey "$OUT_DIR/pem/leaf.key.pem" \
  -in "$OUT_DIR/pem/leaf.cert.pem" \
  -certfile "$OUT_DIR/pem/root.cert.pem" \
  -out "$OUT_DIR/pkcs12/keystore.p12" \
  -passout pass:"$P12_PASS"

# PKCS#8 outputs
# Private key (unencrypted)
openssl pkcs8 -topk8 -in "$OUT_DIR/pem/leaf.key.pem" -nocrypt \
  -out "$OUT_DIR/pkcs8/key_pkcs8_unenc.pem"
# Private key (encrypted)
openssl pkcs8 -topk8 -in "$OUT_DIR/pem/leaf.key.pem" \
  -passout pass:"$PKCS8_PASS" \
  -out "$OUT_DIR/pkcs8/key_pkcs8_encrypted.pem"
# Public key (SPKI, PKCS#8)
openssl pkey -in "$OUT_DIR/pem/leaf.key.pem" -pubout -out "$OUT_DIR/pkcs8/pubkey_pkcs8.pem"

# Generate OpenSSH Ed25519 keys
# Unencrypted
ssh-keygen -t ed25519 -f "$OUT_DIR/openssh/id_ed25519" -N "" -C "keyprobe@test" >/dev/null
# Encrypted
ssh-keygen -t ed25519 -f "$OUT_DIR/openssh/id_ed25519_enc" -N "$SSH_PASS" -C "keyprobe@test" >/dev/null

# Create a JKS keystore and import the root certificate
keytool -genkeypair -alias leaf \
  -keyalg RSA -keysize 2048 -validity 365 \
  -dname "CN=leaf.example.com, O=KeyProbe Test, C=FR" \
  -keystore "$OUT_DIR/jks/test.jks" \
  -storetype JKS \
  -storepass "$JKS_PASS" -keypass "$JKS_PASS" >/dev/null

keytool -importcert -alias root \
  -file "$OUT_DIR/pem/root.cert.pem" \
  -keystore "$OUT_DIR/jks/test.jks" \
  -storetype JKS \
  -storepass "$JKS_PASS" -noprompt >/dev/null

# Misc: unknown/opaque sample
printf 'hello-keyprobe\n' > "$OUT_DIR/misc/unknown.bin"

echo "Fixtures generated under: $OUT_DIR"
