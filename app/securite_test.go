package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMdpValide(t *testing.T) {
	h := hacher("sel", "secret")
	if !strings.HasPrefix(h, prefixeMdp) {
		t.Fatalf("hash %q", h)
	}
	if ok, ancien := mdpValide("sel", "secret", h); !ok || ancien {
		t.Fatalf("ok=%v ancien=%v", ok, ancien)
	}
	if ok, _ := mdpValide("sel", "autre", h); ok {
		t.Fatal("wrong password accepted")
	}
	if ok, _ := mdpValide("autre", "secret", h); ok {
		t.Fatal("wrong salt accepted")
	}
	if ok, ancien := mdpValide("sel", "secret", hacherAncien("sel", "secret")); !ok || !ancien {
		t.Fatalf("old hash: ok=%v ancien=%v", ok, ancien)
	}
	if ok, ancien := mdpValide("sel", "secret", deriverMdp("sel", "secret", 1000)); !ok || !ancien {
		t.Fatalf("weak iterations: ok=%v ancien=%v", ok, ancien)
	}
	for _, mauvais := range []string{prefixeMdp, prefixeMdp + "x$00", prefixeMdp + "0$00", prefixeMdp + "999999999999$00", ""} {
		if ok, _ := mdpValide("sel", "secret", mauvais); ok {
			t.Fatalf("%q accepted", mauvais)
		}
	}
}

func deverrouillerEssai(s *Serveur, mdp string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/deverrouiller", strings.NewReader(`{"mot_de_passe":"`+mdp+`"}`))
	s.apiDeverrouiller(w, r)
	return w
}

func TestDeverrouillerLocalBloqueEtMigre(t *testing.T) {
	s := &Serveur{}
	s.config.Sel = "sel"
	ancien := hacherAncien("sel", "secret")
	s.config.MotDePasseHash = ancien
	for i := 0; i < essaisMdpLocalMax; i++ {
		if w := deverrouillerEssai(s, "faux"); w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d", i, w.Code)
		}
	}
	if w := deverrouillerEssai(s, "secret"); w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Fatalf("not blocked: %d", w.Code)
	}
	s.mu.Lock()
	s.blocageMdp = time.Now().Add(-time.Second)
	s.mu.Unlock()
	if w := deverrouillerEssai(s, "secret"); w.Code != http.StatusOK {
		t.Fatalf("right password refused: %d %s", w.Code, w.Body)
	}
	if s.essaisMdp != 0 || s.session == "" {
		t.Fatalf("essais=%d session=%q", s.essaisMdp, s.session)
	}
	if s.config.MotDePasseHash == ancien || !strings.HasPrefix(s.config.MotDePasseHash, prefixeMdp) || s.config.Sel == "sel" {
		t.Fatalf("hash not upgraded: %q", s.config.MotDePasseHash)
	}
	if ok, vieux := mdpValide(s.config.Sel, "secret", s.config.MotDePasseHash); !ok || vieux {
		t.Fatalf("upgraded hash: ok=%v ancien=%v", ok, vieux)
	}
}

func TestRTKSommeVerifiee(t *testing.T) {
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	contenu := []byte("#!/bin/sh\n")
	_ = tw.WriteHeader(&tar.Header{Name: "rtk", Mode: 0o755, Size: int64(len(contenu)), Typeflag: tar.TypeReg})
	_, _ = tw.Write(contenu)
	tw.Close()
	gz.Close()
	h := sha256.Sum256(b.Bytes())
	dest := filepath.Join(t.TempDir(), "rtk")
	if err := verifierEtExtraireRTK(b.Bytes(), strings.Repeat("0", 64), dest); err == nil {
		t.Fatal("wrong checksum accepted")
	}
	if _, err := os.Stat(dest); err == nil {
		t.Fatal("file written despite a wrong checksum")
	}
	if err := verifierEtExtraireRTK(b.Bytes(), hex.EncodeToString(h[:]), dest); err != nil {
		t.Fatal(err)
	}
	if err := telechargerRTK("inconnu", dest); err == nil {
		t.Fatal("unknown target accepted")
	}
	for _, c := range [][2]string{{"linux", "amd64"}, {"linux", "arm64"}, {"darwin", "arm64"}, {"darwin", "amd64"}} {
		if len(sommesRTK[cibleRTK(c[0], c[1])]) != 64 {
			t.Fatalf("no checksum for %s/%s", c[0], c[1])
		}
	}
}

func TestMajDesactiveeParDefaut(t *testing.T) {
	t.Setenv("ATHANOR_MAJ_API", "")
	if apiDerniereVersion() != "" {
		t.Fatal("an update source is set by default")
	}
	if ok, _ := majPossible(Kit{t.TempDir()}); ok {
		t.Fatal("update possible without a source")
	}
}
