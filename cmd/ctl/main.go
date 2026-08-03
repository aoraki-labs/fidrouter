// ctl mocks the CONTROL PLANE (what New API becomes): it generates keys, seals
// the upstream account pool (managed-key mode), and mints capability tokens.
// It never sees prompts. Usage:
//
//	ctl init                         # generate keys.json, print client pins
//	ctl seal-pool                    # pool.plain.json -> pool.sealed.json (ciphertext)
//	ctl mint -tenant cust1 -pool shared -models gpt-4o,claude-3 -ttl 3600 [-isolated]
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"fidrouter/internal/config"
	"fidrouter/internal/kms"
	"fidrouter/internal/tee"
	"fidrouter/internal/token"
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
	case "remeasure": // overwrite ExpectedMeasurement (e.g. to a real MRTD) before seal-pool
		k := loadKeys()
		k.ExpectedMeasurement = os.Args[2]
		writeJSON(filepath.Join(dir(), "keys.json"), k)
		fmt.Println("ExpectedMeasurement =", os.Args[2])
	default:
		fmt.Println("unknown subcommand:", os.Args[1])
		os.Exit(2)
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
