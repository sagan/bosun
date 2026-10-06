package realityscan

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"
)

func TestRecordLengthsAcrossReadBoundaries(t *testing.T) {
	for _, length := range []int{8192, 8193, 8273, 17408} {
		// A fake TLS header in the payload must not be counted as a record.
		payload := bytes.Repeat([]byte{23, 3, 3, 255, 255}, length/5+1)[:length-5]
		wire := append([]byte{23, 3, 3, byte((length - 5) >> 8), byte(length - 5)}, payload...)
		wire = append([]byte{20, 3, 3, 0, 1, 1}, wire...)
		wire = append(wire, []byte{23, 3, 3, 0, 0}...)
		for _, chunk := range []int{1, 2, 5, 17, len(wire)} {
			var c recordConn
			for p := wire; len(p) > 0; {
				n := min(chunk, len(p))
				c.observe(p[:n])
				p = p[n:]
			}
			if c.maxRecord != length || c.headerN != 0 || c.remaining != 0 {
				t.Fatalf("record=%d chunk=%d got=%+v", length, chunk, c)
			}
		}
	}
}

func TestProbeMeasuresOCSPOnWire(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"example.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	k, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: k}))
	if err != nil {
		t.Fatal(err)
	}
	for _, large := range []bool{false, true} {
		t.Run(map[bool]string{false: "small", true: "large_OCSP"}[large], func(t *testing.T) {
			c := cert
			if large {
				c.OCSPStaple = bytes.Repeat([]byte{1}, 8500)
			}
			ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{c}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"h2"}, CurvePreferences: []tls.CurveID{tls.X25519}})
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			done := make(chan error, 1)
			go func() {
				conn, err := ln.Accept()
				if err == nil {
					defer conn.Close()
					_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
					err = conn.(*tls.Conn).Handshake()
				}
				done <- err
			}()
			r := Probe(context.Background(), "example.com", Options{SkipHTTP: true, Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, ln.Addr().String())
			}})
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if !r.TLS13 || !r.H2 || !r.X25519 || r.TLSRecordOK == nil || *r.TLSRecordOK == large || r.TLSRecordLimit != targetRecordLimit {
				t.Fatalf("unexpected result %+v", r)
			}
			// Both fixtures have the same small DER certificate. The large
			// case fails the record bound because of its stapled extension.
			if large && (r.Feasible || r.ReasonCode != "tls_record_too_large" || r.TLSRecordBytes <= targetRecordLimit) {
				t.Fatalf("oversized record accepted: %+v", r)
			}
			if !large && r.TLSRecordBytes <= len(der) {
				t.Fatalf("not a wire measurement: %+v", r)
			}
		})
	}
}
