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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// untrustedPostgres stands in for a party on the network path: it accepts Postgres' SSLRequest and completes
// TLS with a self-signed certificate for localhost, then hangs up. It reports each finished handshake.
func untrustedPostgres(t *testing.T) (addr string, handshakes <-chan struct{}) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	done := make(chan struct{}, 16)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				var req [8]byte
				if _, err := io.ReadFull(c, req[:]); err != nil || binary.BigEndian.Uint32(req[4:]) != 80877103 {
					return
				}
				if _, err := c.Write([]byte{'S'}); err != nil {
					return
				}
				srv := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
				if srv.Handshake() == nil {
					done <- struct{}{}
				}
			}(conn)
		}
	}()
	return ln.Addr().String(), done
}

// otherCA writes a CA bundle that did not sign the untrusted server's certificate.
func otherCA(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "pinned database CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	return path
}

func TestVerifyFullRefusesAnUntrustedServer(t *testing.T) {
	addr, handshakes := untrustedPostgres(t)
	ca := otherCA(t)

	for name, query := range map[string]string{
		"system roots": "sslmode=verify-full",
		"pinned CA":    "sslmode=verify-full&sslrootcert=" + ca,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := NewPool(context.Background(), "postgres://pat:pw@"+addr+"/pat?"+query, 1)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "certificate")

			err = Migrate("pgx5://pat:pw@" + addr + "/pat?" + query)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "certificate")
		})
	}
	assert.Empty(t, handshakes, "a verify-full client completed TLS with an untrusted server")
}

// Control for the test above: sslmode=require does finish the handshake with the same server, which is the
// unauthenticated link verify-full exists to refuse.
func TestRequireAcceptsAnUntrustedServer(t *testing.T) {
	addr, handshakes := untrustedPostgres(t)

	_, err := NewPool(context.Background(), "postgres://pat:pw@"+addr+"/pat?sslmode=require", 1)
	require.Error(t, err)

	select {
	case <-handshakes:
	case <-time.After(5 * time.Second):
		t.Fatal("sslmode=require did not complete TLS with the untrusted server")
	}
}
