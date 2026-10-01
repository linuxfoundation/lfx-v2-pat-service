// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package postgres

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// impostor accepts Postgres SSLRequests and completes TLS with the given certificate. It counts the startup
// messages that arrive over TLS: a startup message is where the client starts to authenticate.
type impostor struct {
	addr     string
	startups atomic.Int32
}

// testCA is a certificate authority that signs server certificates; its PEM is written to rootFile.
type testCA struct {
	cert     *x509.Certificate
	key      *ecdsa.PrivateKey
	rootFile string
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	rootFile := filepath.Join(t.TempDir(), "root.crt")
	require.NoError(t, os.WriteFile(rootFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	return &testCA{cert: cert, key: key, rootFile: rootFile}
}

// issue signs a server certificate for the given names. A nil CA self-signs.
func (ca *testCA) issue(t *testing.T, dnsNames []string, ips []net.IP) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "server"},
		DNSNames:     dnsNames,
		IPAddresses:  ips,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	parent, signer := tmpl, key
	if ca != nil {
		parent, signer = ca.cert, ca.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, signer)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func newImpostor(t *testing.T, cert tls.Certificate) *impostor {
	t.Helper()
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	s := &impostor{addr: ln.Addr().String()}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(conn, tlsCfg)
		}
	}()
	return s
}

func (s *impostor) serve(conn net.Conn, cfg *tls.Config) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	req := make([]byte, 8)
	if _, err := io.ReadFull(conn, req); err != nil || binary.BigEndian.Uint32(req[4:]) != 80877103 {
		return
	}
	if _, err := conn.Write([]byte{'S'}); err != nil {
		return
	}
	tlsConn := tls.Server(conn, cfg)
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(tlsConn, hdr); err == nil {
		s.startups.Add(1)
	}
}

func (s *impostor) url(scheme, sslmode, sslrootcert string) string {
	q := url.Values{"sslmode": {sslmode}}
	if sslrootcert != "" {
		q.Set("sslrootcert", sslrootcert)
	}
	u := url.URL{
		Scheme:   scheme,
		User:     url.UserPassword("pat", "S3cr3t"),
		Host:     s.addr,
		Path:     "/pat",
		RawQuery: q.Encode(),
	}
	return u.String()
}

// isolatePGEnv clears the PG* variables pgx merges into the parsed config, so the URL alone decides.
func isolatePGEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"PGSSLROOTCERT", "PGSSLMODE", "PGSSLCERT", "PGSSLKEY", "PGSSLNEGOTIATION", "PGSSLSNI",
		"PGSERVICE", "PGSERVICEFILE"} {
		t.Setenv(k, "")
	}
}

func TestUntrustedServerCertificateIsRefused(t *testing.T) {
	isolatePGEnv(t)
	var selfSigned *testCA
	srv := newImpostor(t, selfSigned.issue(t, []string{"localhost"}, []net.IP{net.IPv4(127, 0, 0, 1)}))

	_, err := NewPool(context.Background(), srv.url("postgres", "verify-full", ""), 1)
	require.Error(t, err)
	assert.ErrorContains(t, err, "certificate")

	err = Migrate(srv.url("pgx5", "verify-full", ""))
	require.Error(t, err)
	assert.ErrorContains(t, err, "certificate")

	assert.Zero(t, srv.startups.Load(), "verify-full must not start authenticating to an untrusted server")

	// Control: sslmode=require completes TLS with the impostor and starts authenticating, which is why it is refused.
	_, err = NewPool(context.Background(), srv.url("postgres", "require", ""), 1)
	require.Error(t, err)
	assert.Positive(t, srv.startups.Load(), "the impostor should have received a startup message under require")
}

func TestPinnedCAVerifiesChainAndHostName(t *testing.T) {
	isolatePGEnv(t)
	ca := newTestCA(t)

	// A certificate from the pinned CA for the dialled address is accepted: both connections reach the startup
	// message (the impostor then hangs up, so they still fail).
	good := newImpostor(t, ca.issue(t, nil, []net.IP{net.IPv4(127, 0, 0, 1)}))
	_, err := NewPool(context.Background(), good.url("postgres", "verify-full", ca.rootFile), 1)
	require.Error(t, err)
	afterPool := good.startups.Load()
	assert.Positive(t, afterPool, "pool should authenticate to a server the pinned CA vouches for")
	require.Error(t, Migrate(good.url("pgx5", "verify-full", ca.rootFile)))
	assert.Greater(t, good.startups.Load(), afterPool, "migrator should authenticate to a server the pinned CA vouches for")

	// A certificate from the same CA for another host is refused: this is what verify-ca would have accepted.
	other := newImpostor(t, ca.issue(t, []string{"other.example"}, nil))
	_, err = NewPool(context.Background(), other.url("postgres", "verify-full", ca.rootFile), 1)
	require.Error(t, err)
	assert.ErrorContains(t, err, "certificate")
	err = Migrate(other.url("pgx5", "verify-full", ca.rootFile))
	require.Error(t, err)
	assert.ErrorContains(t, err, "certificate")
	assert.Zero(t, other.startups.Load(), "verify-full must not authenticate to a host the certificate does not name")
}
