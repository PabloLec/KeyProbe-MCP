#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="${1:-tests/fixtures}"
umask 077

# Dépendances (Ubuntu/Debian) :
#   sudo apt-get update && sudo apt-get install -y openssl openjdk-17-jre-headless openssh-client

# Passwords de test
P12_PASS="changeit"
JKS_PASS="changeit"
PKCS8_PASS="secret"
SSH_PASS="secret"

# Dossiers
mkdir -p "$OUT_DIR"/{pem,der,pkcs7,pkcs12,pkcs8,openssh,jks,misc}

# --- 1) CA racine + Leaf (RSA) ----------------------------------------------------
# Root (auto-signé)
openssl req -x509 -newkey rsa:2048 -sha256 -days 730 -nodes \
  -subj "/CN=KeyProbe Test Root/O=KeyProbe Test/C=FR" \
  -keyout "$OUT_DIR/pem/root.key.pem" \
  -out "$OUT_DIR/pem/root.cert.pem"

# Leaf CSR
openssl req -newkey rsa:2048 -nodes -sha256 \
  -subj "/CN=leaf.example.com/O=KeyProbe Test/C=FR" \
  -keyout "$OUT_DIR/pem/leaf.key.pem" \
  -out "$OUT_DIR/pem/leaf.csr.pem"

# SAN config temporaire
SAN_CFG="$(mktemp)"
cat >"$SAN_CFG" <<EOF
basicConstraints=CA:FALSE
subjectAltName=DNS:leaf.example.com,IP:127.0.0.1
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,clientAuth
EOF

# Signer le leaf avec la racine
openssl x509 -req -in "$OUT_DIR/pem/leaf.csr.pem" \
  -CA "$OUT_DIR/pem/root.cert.pem" -CAkey "$OUT_DIR/pem/root.key.pem" -CAcreateserial \
  -out "$OUT_DIR/pem/leaf.cert.pem" -days 365 -sha256 -extfile "$SAN_CFG"

rm -f "$SAN_CFG" "$OUT_DIR/pem/root.cert.srl" || true

# Chaîne PEM (leaf + root)
cat "$OUT_DIR/pem/leaf.cert.pem" "$OUT_DIR/pem/root.cert.pem" > "$OUT_DIR/pem/chain.pem"

# --- 2) DER -----------------------------------------------------------------------
openssl x509 -in "$OUT_DIR/pem/leaf.cert.pem" -outform DER -out "$OUT_DIR/der/leaf.cert.der"

# --- 3) PKCS#7 (P7B) --------------------------------------------------------------
# DER
openssl crl2pkcs7 -nocrl \
  -certfile "$OUT_DIR/pem/leaf.cert.pem" -certfile "$OUT_DIR/pem/root.cert.pem" \
  -out "$OUT_DIR/pkcs7/chain.p7b" -outform DER

# PEM
openssl crl2pkcs7 -nocrl \
  -certfile "$OUT_DIR/pem/chain.pem" \
  -out "$OUT_DIR/pkcs7/chain.pem.p7b"

# --- 4) PKCS#12 -------------------------------------------------------------------
openssl pkcs12 -export -name "leaf" \
  -inkey "$OUT_DIR/pem/leaf.key.pem" \
  -in "$OUT_DIR/pem/leaf.cert.pem" \
  -certfile "$OUT_DIR/pem/root.cert.pem" \
  -out "$OUT_DIR/pkcs12/keystore.p12" \
  -passout pass:"$P12_PASS"

# --- 5) PKCS#8 (privé non chiffré / chiffré + public) -----------------------------
openssl pkcs8 -topk8 -in "$OUT_DIR/pem/leaf.key.pem" -nocrypt \
  -out "$OUT_DIR/pkcs8/key_pkcs8_unenc.pem"

openssl pkcs8 -topk8 -in "$OUT_DIR/pem/leaf.key.pem" \
  -passout pass:"$PKCS8_PASS" \
  -out "$OUT_DIR/pkcs8/key_pkcs8_encrypted.pem"

# Public (PKCS#8)
openssl pkey -in "$OUT_DIR/pem/leaf.key.pem" -pubout -out "$OUT_DIR/pkcs8/pubkey_pkcs8.pem"

# --- 6) OpenSSH (ed25519) ---------------------------------------------------------
# Non chiffré
ssh-keygen -t ed25519 -f "$OUT_DIR/openssh/id_ed25519" -N "" -C "keyprobe@test" >/dev/null
# Chiffré
ssh-keygen -t ed25519 -f "$OUT_DIR/openssh/id_ed25519_enc" -N "$SSH_PASS" -C "keyprobe@test" >/dev/null

# --- 7) JKS -----------------------------------------------------------------------
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

# --- 8) UNKNOWN / divers ----------------------------------------------------------
printf 'hello-keyprobe\n' > "$OUT_DIR/misc/unknown.bin"

echo "Fixtures generated under: $OUT_DIR"
