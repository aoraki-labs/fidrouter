package tee

// TdxConfigfs is a REAL attester: it produces genuine Intel TDX quotes via the
// Linux configfs-TSM interface (/sys/kernel/config/tsm/report), no vendor tools.
// It is the production counterpart to Mock — same tee.Attester interface.
//
// report_data (64B, first 32 = SHA-256) binds: nonce || ephemeral_pub || identity_pub.
// So a client that DCAP-verifies the quote also pins the channel key AND the
// receipt-signing key to the attested measurement.
//
// Requires root (configfs write) and a TDX guest. Measurement() = MRTD (hex).

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"fidrouter/internal/enc"
)

const tsmReportDir = "/sys/kernel/config/tsm/report"

// quote byte offsets (TDX quote v4): header 48 + TD body; MRTD at body+136.
const mrtdAbsOff = 48 + 136

type TdxConfigfs struct {
	idPriv      ed25519.PrivateKey
	measurement string
	tlsPub      []byte // RA-TLS: DER SPKI of the in-enclave TLS cert key (bound into report_data)
	ctr         uint64
	mu          sync.Mutex
	sess        map[string]sessionEntry
}

// NewTdxConfigfs generates a boot quote (zero report_data) to read the MRTD.
func NewTdxConfigfs(idPriv ed25519.PrivateKey) (*TdxConfigfs, error) {
	t := &TdxConfigfs{idPriv: idPriv, sess: make(map[string]sessionEntry)}
	raw, err := t.genQuote(make([]byte, 64))
	if err != nil {
		return nil, err
	}
	if len(raw) < mrtdAbsOff+48 {
		return nil, errors.New("tdx: quote too short to read MRTD")
	}
	t.measurement = hex.EncodeToString(raw[mrtdAbsOff : mrtdAbsOff+48])
	return t, nil
}

func (t *TdxConfigfs) Platform() string               { return "gcp-tdx" }
func (t *TdxConfigfs) Measurement() string            { return t.measurement }
func (t *TdxConfigfs) IdentityPub() ed25519.PublicKey { return t.idPriv.Public().(ed25519.PublicKey) }
func (t *TdxConfigfs) Sign(msg []byte) []byte         { return ed25519.Sign(t.idPriv, msg) }
func (t *TdxConfigfs) SetTLSPub(spki []byte)          { t.tlsPub = spki }

func (t *TdxConfigfs) Attest(nonce []byte) (Quote, error) {
	priv, err := enc.NewX25519()
	if err != nil {
		return Quote{}, err
	}
	ephPub := priv.PublicKey().Bytes()
	idPub := t.IdentityPub()

	// report_data = SHA256(nonce || ephemeral_pub || identity_pub [|| tls_pub]), padded to 64B
	h := sha256.New()
	h.Write(nonce)
	h.Write(ephPub)
	h.Write(idPub)
	if len(t.tlsPub) > 0 { // RA-TLS: bind the TLS cert public key into report_data
		h.Write(t.tlsPub)
	}
	reportData := make([]byte, 64)
	copy(reportData, h.Sum(nil))

	raw, err := t.genQuote(reportData)
	if err != nil {
		return Quote{}, err
	}

	sid := make([]byte, 16)
	if _, err := rand.Read(sid); err != nil {
		return Quote{}, err
	}
	session := hex.EncodeToString(sid)
	t.mu.Lock()
	t.gcLocked()
	t.sess[session] = sessionEntry{priv: priv, exp: time.Now().Add(2 * time.Minute)}
	t.mu.Unlock()

	return Quote{
		Platform: "gcp-tdx", Measurement: t.measurement, Session: session,
		Nonce: nonce, EphemeralPub: ephPub, IdentityPub: idPub, TLSPub: t.tlsPub, RawQuote: raw,
	}, nil
}

func (t *TdxConfigfs) SessionKey(session string, clientPub []byte) ([]byte, error) {
	t.mu.Lock()
	e, ok := t.sess[session]
	t.mu.Unlock()
	if !ok || time.Now().After(e.exp) {
		return nil, errors.New("tdx: unknown or expired session")
	}
	return enc.SharedKey(e.priv, clientPub, "fid-e2e-v1")
}

// genQuote drives configfs-TSM: mkdir a report entry, write report_data to
// inblob, read outblob (the TDX quote), rmdir.
func (t *TdxConfigfs) genQuote(reportData []byte) ([]byte, error) {
	n := atomic.AddUint64(&t.ctr, 1)
	dir := filepath.Join(tsmReportDir, "fidproxy"+hex.EncodeToString([]byte{byte(n), byte(n >> 8)})+strconvItoa(int(n)))
	if err := os.Mkdir(dir, 0o700); err != nil {
		return nil, err
	}
	defer os.Remove(dir)
	if err := os.WriteFile(filepath.Join(dir, "inblob"), reportData, 0o600); err != nil {
		return nil, err
	}
	return os.ReadFile(filepath.Join(dir, "outblob"))
}

func (t *TdxConfigfs) gcLocked() {
	now := time.Now()
	for k, v := range t.sess {
		if now.After(v.exp) {
			delete(t.sess, k)
		}
	}
}

func strconvItoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}
