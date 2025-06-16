package keys

import (
	"crypto/rsa"
	"crypto/x509"
	"embed"
	"encoding/pem"
	"errors"
	"path/filepath"
)

//go:embed files/*
var files embed.FS

func readFile(name string) []byte {
	file, err := files.ReadFile(filepath.Join("files", name))
	if err != nil {
		panic(err)
	}
	return file
}

type Key string

const (
	GatewayPublic Key = "gateway.public.pem"
	IDPPublic     Key = "idp.public.pem"
)

func (k Key) GetRSA() (*rsa.PublicKey, error) {
	content := readFile(string(k))

	block, _ := pem.Decode(content)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("failed to decode PEM block containing public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	key, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not RSA public key")
	}
	return key, nil
}
