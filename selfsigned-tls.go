package selfsignedtlsgo

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

// Config allows the self-signed certificate to be customized
type Config struct {
	CommonName         string
	Country            string
	Organization       string
	OrganizationalUnit string
	ExpiryDays         int
	SubjectKeyId       []byte
}

// DefaultConfig is useful for testing
func DefaultConfig() *Config {
	return &Config{
		CommonName:         "localhost",
		Country:            "dev",
		Organization:       "dev",
		OrganizationalUnit: "dev",
		ExpiryDays:         1,
		SubjectKeyId:       []byte{113, 117, 105, 99, 107, 115, 101, 114, 118, 101},
	}
}

// DefaultSelfsignedTls uses DefaultConfig to generate a self-signed tls.Certificate
func DefaultSelfsignedTls() (tls.Certificate, error) {
	return NewSelfsignedTls(DefaultConfig())
}

// NewSelfsignedTls expects a Config to generate a self-signed tls.Certificate
func NewSelfsignedTls(cfg *Config) (tls.Certificate, error) {
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.Unix()),
		Subject: pkix.Name{
			CommonName:         cfg.CommonName,
			Country:            []string{cfg.Country},
			Organization:       []string{cfg.Organization},
			OrganizationalUnit: []string{cfg.OrganizationalUnit},
		},
		NotBefore:             now,
		NotAfter:              now.AddDate(0, 0, cfg.ExpiryDays),
		SubjectKeyId:          cfg.SubjectKeyId,
		BasicConstraintsValid: true,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	cert, err := x509.CreateCertificate(rand.Reader, template, template,
		priv.Public(), priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	var outCert tls.Certificate
	outCert.Certificate = append(outCert.Certificate, cert)
	outCert.PrivateKey = priv

	return outCert, nil
}
