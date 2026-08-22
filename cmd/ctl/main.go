// ctl mocks the CONTROL PLANE (what New API becomes): it generates keys, seals
// the upstream account pool (managed-key mode), and mints capability tokens.
// It never sees prompts. Usage:
//
//	ctl init                         # generate keys.json, print client pins
//	ctl seal-pool                    # pool.plain.json -> pool.sealed.json (ciphertext)
//	ctl mint -tenant cust1 -pool shared -models gpt-4o,claude-3 -ttl 3600 [-isolated]
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fidrouter/internal/config"
	"fidrouter/pkg/enc"
	"fidrouter/internal/kms"
	"fidrouter/pkg/tee"
	"fidrouter/pkg/token"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: ctl <init|seal-pool|mint> ...")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "init":
		cmdInit()
	case "seal-pool":
		cmdSealPool()
	case "mint":
		cmdMint(os.Args[2:])
	case "seal-byok": // customer seals an upstream key to the attested enclave (operator-blind)
		cmdSealBYOK(os.Args[2:])
	case "remeasure": // overwrite ExpectedMeasurement (e.g. to a real MRTD) before seal-pool
		k := loadKeys()
		k.ExpectedMeasurement = os.Args[2]
		writeJSON(filepath.Join(dir(), "keys.json"), k)
		fmt.Println("ExpectedMeasurement =", os.Args[2])
	case "publish-public": // write config/public.json (cp_pub + expected measurement) — the
		// ONLY key material safe to bake into the image. Regenerate after `init` so the
		// baked cp_pub matches the control-plane signing key.
		k := loadKeys()
		writeJSON(filepath.Join(dir(), "public.json"), config.PublicConfig{
			CPPub: k.CPPub, ExpectedMeasurement: k.ExpectedMeasurement,
		})
		fmt.Println("wrote public.json (cp_pub matches current keys.json)")
	default:
		fmt.Println("unknown subcommand:", os.Args[1])
		os.Exit(2)
	}
}

// cmdSealBYOK is the KEY OWNER's tool: it verifies the enclave, then encrypts the
// upstream key to the enclave's per-boot sealing pubkey so ONLY that measured
// enclave can open it. The operator only ever handles the ciphertext → operator-blind.
func cmdSealBYOK(args []string) {
	fs := flag.NewFlagSet("seal-byok", flag.ExitOnError)
	endpoint := fs.String("endpoint", "http://127.0.0.1:9090", "enclave base URL")
	keyStr := fs.String("key", "", "upstream key to seal (else read stdin)")
	pin := fs.String("pin", "", "expected measurement (optional but recommended)")
	account := fs.String("account", "", "if set with -token, also POST /byok to provision it")
	tok := fs.String("token", "", "capability token (authority for /byok submit)")
	idpubPin := fs.String("idpub", "", "expected enclave identity pubkey, hex (STRONGLY recommended: "+
		"this command does not verify the hardware quote, so pinning the identity key is what "+
		"makes a man-in-the-middle unable to substitute its own sealing key)")
	_ = fs.Parse(args)

	upstream := *keyStr
	if upstream == "" {
		b, _ := io.ReadAll(os.Stdin)
		upstream = strings.TrimSpace(string(b))
	}
	if upstream == "" {
		fatal(fmt.Errorf("no upstream key (pass -key or pipe via stdin)"))
	}

	// 1) attestation → identity pub (+ optional measurement pin)
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	var q struct {
		Measurement string `json:"measurement"`
		IdentityPub []byte `json:"identity_pub"`
	}
	getJSON(*endpoint+"/attestation?nonce="+hex.EncodeToString(nonce), &q)
	if *pin != "" && q.Measurement != *pin {
		fatal(fmt.Errorf("measurement mismatch — got %s want %s (refusing to seal to an unknown build)", q.Measurement, *pin))
	}
	// 2) sealing pub, signed by the (attested) identity key
	var sp struct {
		SealingPub  string `json:"sealing_pub"`
		Sig         string `json:"sig"`
		IdentityPub string `json:"identity_pub"`
	}
	getJSON(*endpoint+"/sealing", &sp)
	sealingPub, _ := base64.StdEncoding.DecodeString(sp.SealingPub)
	sig, _ := base64.StdEncoding.DecodeString(sp.Sig)
	idpub := q.IdentityPub // from the (mock) quote; on Confidential Space it's in /sealing
	if len(idpub) == 0 {
		idpub, _ = base64.StdEncoding.DecodeString(sp.IdentityPub)
	}
	if *idpubPin != "" {
		want, err := hex.DecodeString(strings.TrimPrefix(*idpubPin, "0x"))
		if err != nil {
			fatal(fmt.Errorf("-idpub is not valid hex: %w", err))
		}
		if !bytes.Equal(want, idpub) {
			fatal(fmt.Errorf("identity pubkey mismatch — got %x want %x (refusing to seal: "+
				"this is not the enclave you pinned)", idpub, want))
		}
	}
	if !ed25519.Verify(ed25519.PublicKey(idpub), sealingPub, sig) {
		fatal(fmt.Errorf("sealing pubkey signature invalid — not signed by the attested enclave identity"))
	}
	// NOTE: full CS attestation-token verification (that this identity belongs to the
	// pinned measurement) is done by the verify SDK on the inference path; here we pin
	// the measurement and (with -idpub) the identity key, then verify the sealing-key
	// signature — which only the holder of the identity seed can produce.
	// 3) seal upstream key to sealing pub: blob = client_eph_pub || AES-GCM(shared, key)
	eph, err := enc.NewX25519()
	if err != nil {
		fatal(err)
	}
	k, err := enc.SharedKey(eph, sealingPub, "fid-byok-v1")
	if err != nil {
		fatal(err)
	}
	ct, err := enc.Seal(k, []byte(upstream), []byte("fid-byok-v1"))
	if err != nil {
		fatal(err)
	}
	sealed := "sealed:" + base64.StdEncoding.EncodeToString(append(eph.PublicKey().Bytes(), ct...))

	if *account != "" && *tok != "" { // submit to /byok
		body, _ := json.Marshal(map[string]string{"token": *tok, "account": *account, "sealed": sealed})
		resp, err := httpc().Post(*endpoint+"/byok", "application/json", bytes.NewReader(body))
		if err != nil {
			fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		fmt.Printf("POST /byok -> %d %s\n", resp.StatusCode, strings.TrimSpace(string(b)))
	} else {
		fmt.Println(sealed) // hand this ciphertext to the operator; they never see plaintext
	}
}

// httpc talks to an enclave that may serve RA-TLS. Under RA-TLS the certificate is
// generated inside the enclave per boot and self-signed — there is no CA to chain to, so
// CA validation is deliberately skipped. The trust anchor for every operation here is NOT
// the transport: it is (a) the pinned measurement and (b) the sealing key's Ed25519
// signature by the enclave's attested identity key, which only the real enclave (holder of
// the identity seed) can produce. Use -idpub to pin that identity key.
func httpc() *http.Client {
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, // nolint:gosec
	}
}

func getJSON(url string, v any) {
	resp, err := httpc().Get(url)
	if err != nil {
		fatal(err)
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		fatal(err)
	}
}

func dir() string {
	d := os.Getenv("FID_HOME")
	if d == "" {
		d = "config"
	}
	_ = os.MkdirAll(d, 0o755)
	return d
}

func cmdInit() {
	idPub, idPriv, _ := ed25519.GenerateKey(rand.Reader)
	cpPub, cpPriv, _ := ed25519.GenerateKey(rand.Reader)
	master := make([]byte, 32)
	_, _ = rand.Read(master)

	k := config.Keys{
		IdentitySeed:        idPriv.Seed(),
		IdentityPub:         idPub,
		CPSeed:              cpPriv.Seed(),
		CPPub:               cpPub,
		KMSMaster:           master,
		ExpectedMeasurement: tee.MeasurementOf(config.ProxyVersion, false),
	}
	writeJSON(filepath.Join(dir(), "keys.json"), k)

	// sourceable pins for the demo / client SDK
	pins := fmt.Sprintf("export PIN_MEASUREMENT=%s\nexport PIN_IDPUB=%s\n",
		k.ExpectedMeasurement, hex.EncodeToString(idPub))
	_ = os.WriteFile(filepath.Join(dir(), "pins.sh"), []byte(pins), 0o644)

	fmt.Println("initialized. client pins (give these to the client SDK):")
	fmt.Println("  -pin-measurement", k.ExpectedMeasurement)
	fmt.Println("  -pin-idpub      ", hex.EncodeToString(idPub))
}

func cmdSealPool() {
	k := loadKeys()
	var plain config.PlainPools
	readJSON(filepath.Join(dir(), "pool.plain.json"), &plain)

	km := kms.NewMock(k.KMSMaster, k.ExpectedMeasurement)
	out := config.SealedPools{Pools: map[string][]config.SealedAccount{}}
	for pool, accts := range plain.Pools {
		for _, a := range accts {
			sealed, err := km.Seal([]byte(a.Key), k.ExpectedMeasurement)
			if err != nil {
				fatal(err)
			}
			out.Pools[pool] = append(out.Pools[pool], config.SealedAccount{
				ID: a.ID, Provider: a.Provider, BaseURL: a.BaseURL, Sealed: sealed, TPMBudget: a.TPMBudget,
			})
		}
	}
	writeJSON(filepath.Join(dir(), "pool.sealed.json"), out)
	fmt.Println("sealed pool written (control plane now stores ciphertext only)")
}

func cmdMint(args []string) {
	fs := flag.NewFlagSet("mint", flag.ExitOnError)
	tenant := fs.String("tenant", "cust1", "downstream customer id")
	pool := fs.String("pool", "shared", "upstream account pool id")
	models := fs.String("models", "gpt-4o", "comma-separated model allowlist")
	ttl := fs.Int64("ttl", 3600, "seconds")
	isolated := fs.Bool("isolated", false, "forbid cross-tenant cache sharing")
	maxTok := fs.Int64("max-tok", 1_000_000, "quota")
	_ = fs.Parse(args)

	k := loadKeys()
	cpPriv := ed25519.NewKeyFromSeed(k.CPSeed)
	c := token.Claims{
		Tenant: *tenant, Pool: *pool, Models: splitComma(*models),
		MaxTok: *maxTok, Exp: time.Now().Unix() + *ttl, Isolated: *isolated,
	}
	tok, err := token.Mint(cpPriv, c)
	if err != nil {
		fatal(err)
	}
	fmt.Println(tok)
}

func splitComma(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == ',' {
			if cur != "" {
				out = append(out, cur)
			}
			cur = ""
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func loadKeys() config.Keys {
	var k config.Keys
	readJSON(filepath.Join(dir(), "keys.json"), &k)
	return k
}

func writeJSON(path string, v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		fatal(err)
	}
}
func readJSON(path string, v any) {
	b, err := os.ReadFile(path)
	if err != nil {
		fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		fatal(err)
	}
}
func fatal(err error) { fmt.Fprintln(os.Stderr, "ctl:", err); os.Exit(1) }
