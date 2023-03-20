package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/filecoin-project/go-address"

	"golang.org/x/xerrors"
)

const (
	KTBLS       = "bls"
	KTSecp256k1 = "secp256k1"
)

var ValidKeyTypes = []string{KTBLS, KTSecp256k1}

// fcaddr reads a base16 encoded public key from stdin and prints a human readable address as output

func main() {
	var keyType string

	flag.StringVar(&keyType, "type", keyType, fmt.Sprintf("type of public key provided [%s]", strings.Join(ValidKeyTypes, ", ")))
	flag.Parse()

	if len(keyType) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	if !isSupportedKeyType(keyType) {
		fmt.Printf("error: invalid key type provided '%s'", keyType)
		os.Exit(1)
	}

	publicKeyHex, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Printf("error: %s\n", err)
		os.Exit(1)
	}

	publicKeyBytes, err := hex.DecodeString(strings.TrimSpace(string(publicKeyHex)))
	if err != nil {
		fmt.Printf("error: %s\n", err)
		os.Exit(1)
	}

	addr, err := addrFromPubicKeyByType(publicKeyBytes, keyType)
	if err != nil {
		fmt.Printf("error: %s\n", err)
		os.Exit(1)
	}

	fmt.Printf("%s\n", addr)
}

func isSupportedKeyType(keyType string) bool {
	for _, valid := range ValidKeyTypes {
		if valid == keyType {
			return true
		}
	}

	return false
}

func addrFromPubicKeyByType(publicKey []byte, keyType string) (address.Address, error) {
	var addr address.Address
	var err error

	switch keyType {
	case KTSecp256k1:
		addr, err = address.NewSecp256k1Address(publicKey)
		if err != nil {
			return address.Undef, xerrors.Errorf("converting Secp256k1 to address: %w", err)
		}
	case KTBLS:
		addr, err = address.NewBLSAddress(publicKey)
		if err != nil {
			return address.Undef, xerrors.Errorf("converting BLS to address: %w", err)
		}
	default:
		return address.Undef, xerrors.Errorf("unknown key type")
	}

	return addr, nil
}
