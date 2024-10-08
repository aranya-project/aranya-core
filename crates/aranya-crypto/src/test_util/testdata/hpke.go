package main

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strconv"
)

func main() {
	if err := main1(); err != nil {
		panic(err)
	}
}

func main1() error {
	// See https://www.rfc-editor.org/rfc/rfc9180.html#name-test-vectors
	resp, err := http.Get("https://raw.githubusercontent.com/cfrg/draft-irtf-cfrg-hpke/5f503c564da00b0687b3de75f1dfbdfc4079ad31/test-vectors.json")
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var grps []TestGroup
	err = json.Unmarshal(b, &grps)
	if err != nil {
		return err
	}

	m := make(map[triple][]TestGroup)
	for _, g := range grps {
		k := triple{g.Kem, g.Kdf, g.AEAD}
		m[k] = append(m[k], g)
	}
	for k, v := range m {
		b, err := json.Marshal(struct {
			G []TestGroup `json:"test_groups"`
		}{G: v})
		if err != nil {
			return err
		}
		err = os.WriteFile(k.String()+".json", b, 0644)
		if err != nil {
			return err
		}
	}
	return nil
}

type triple struct {
	kem  uint16
	kdf  uint16
	aead uint16
}

func (t triple) String() string {
	s := "Hpke"
	switch t.kem {
	case 0x0010:
		s += "DhKemP256HkdfSha256"
	case 0x0011:
		s += "DhKemP384HkdfSha384"
	case 0x0012:
		s += "DhKemP521HkdfSha512"
	case 0x0020:
		s += "DhKemX25519HkdfSha256"
	case 0x0021:
		s += "DhKemX448HkdfSha512"
	default:
		panic("unknown kem" + strconv.Itoa(int(t.kem)))
	}
	switch t.kdf {
	case 0x0001:
		s += "HkdfSha256"
	case 0x0002:
		s += "HkdfSha384"
	case 0x0003:
		s += "HkdfSha512"
	default:
		panic("unknown kdf" + strconv.Itoa(int(t.kdf)))
	}
	switch t.aead {
	case 0x0001:
		s += "Aes128Gcm"
	case 0x0002:
		s += "Aes256Gcm"
	case 0x0003:
		s += "ChaCha20Poly1305"
	case 0xffff:
		s += "ExportOnly"
	default:
		panic("unknown aead" + strconv.Itoa(int(t.aead)))
	}
	return s
}

type TestGroup struct {
	Mode           uint8        `json:"mode"`
	Kem            uint16       `json:"kem_id"`
	Kdf            uint16       `json:"kdf_id"`
	AEAD           uint16       `json:"aead_id"`
	Info           string       `json:"info"`
	Ikmr           string       `json:"ikmR"`
	Ikms           string       `json:"ikmS"`
	Ikme           string       `json:"ikmE"`
	Skrm           string       `json:"skRm"`
	Sksm           string       `json:"skSm"`
	Skem           string       `json:"skEm"`
	Psk            string       `json:"psk"`
	PskID          string       `json:"psk_id"`
	Pkrm           string       `json:"pkRm"`
	Pksm           string       `json:"pkSm"`
	Pkem           string       `json:"pkEm"`
	Enc            string       `json:"enc"`
	SharedSecret   string       `json:"shared_secret"`
	KsCtx          string       `json:"key_schedule_context"`
	Secret         string       `json:"secret"`
	Key            string       `json:"key"`
	BaseNonce      string       `json:"base_nonce"`
	ExporterSecret string       `json:"exporter_secret"`
	Tests          []Test       `json:"encryptions"`
	Exports        []ExportTest `json:"exports"`
}

type Test struct {
	Aad   string `json:"aad"`
	Ct    string `json:"ct"`
	Nonce string `json:"nonce"`
	Pt    string `json:"pt"`
}

type ExportTest struct {
	ExporterCtx string `json:"exporter_context"`
	Len         int    `json:"L"`
	ExportedVal string `json:"exported_value"`
}
