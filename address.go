package address

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"

	cbor "github.com/ipfs/go-ipld-cbor"
	"github.com/multiformats/go-varint"
	"github.com/polydawn/refmt/obj/atlas"
	cbg "github.com/whyrusleeping/cbor-gen"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/xerrors"
)

func init() {
	cbor.RegisterCborType(addressAtlasEntry)
}

var addressAtlasEntry = atlas.BuildEntry(Address{}).Transform().
	TransformMarshal(atlas.MakeMarshalTransformFunc(
		func(a Address) (string, error) {
			return string(a.Bytes()), nil
		})).
	TransformUnmarshal(atlas.MakeUnmarshalTransformFunc(
		func(x string) (Address, error) {
			return NewFromBytes([]byte(x))
		})).
	Complete()

// CurrentNetwork specifies which network the address belongs to
var CurrentNetwork = Mainnet

// Address is the go type that represents an address in the filecoin network.
type Address struct{ str string }

// Undef is the type that represents an undefined address.
var Undef = Address{}

// Network represents which network an address belongs to.
type Network = byte

const (
	// Mainnet is the main network.
	Mainnet Network = iota
	// Testnet is the test network.
	Testnet
)

// MainnetPrefix is the main network prefix.
const MainnetPrefix = "f"

// TestnetPrefix is the test network prefix.
const TestnetPrefix = "t"

// Protocol represents which protocol an address uses.
type Protocol = byte

const (
	// ID represents the address ID protocol.
	ID Protocol = iota
	// SECP256K1 represents the address SECP256K1 protocol.
	SECP256K1
	// Actor represents the address Actor protocol.
	Actor
	// BLS represents the address BLS protocol.
	BLS
	// Delegated represents the delegated (f4) address protocol.
	Delegated

	Unknown = Protocol(255)
)

// Protocol returns the protocol used by the address.
func (a Address) Protocol() Protocol {
	if len(a.str) == 0 {
		return Unknown
	}
	return a.str[0]
}

// Payload returns the payload of the address.
func (a Address) Payload() []byte {
	if len(a.str) == 0 {
		return nil
	}
	return []byte(a.str[1:])
}

// Bytes returns the address as bytes.
func (a Address) Bytes() []byte {
	return []byte(a.str)
}

// String returns an address encoded as a string.
func (a Address) String() string {
	str, err := encode(CurrentNetwork, a)
	if err != nil {
		panic(err) // I don't know if this one is okay
	}
	return str
}

func (a Address) StringWithNetwork(network Network) string {
	str, err := encode(network, a)
	if err != nil {
		panic(err) // I don't know if this one is okay
	}
	return str
}

// Empty returns true if the address is empty, false otherwise.
func (a Address) Empty() bool {
	return a == Undef
}

// Unmarshal unmarshals the cbor bytes into the address.
func (a Address) Unmarshal(b []byte) error {
	return cbor.DecodeInto(b, &a)
}

// Marshal marshals the address to cbor.
func (a Address) Marshal() ([]byte, error) {
	return cbor.DumpObject(a)
}

// UnmarshalJSON implements the json unmarshal interface.
func (a *Address) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}

	addr, err := decode(s)
	if err != nil {
		return err
	}
	*a = addr
	return nil
}

// MarshalJSON implements the json marshal interface.
func (a Address) MarshalJSON() ([]byte, error) {
	return []byte(`"` + a.String() + `"`), nil
}

func (a *Address) Scan(value interface{}) error {
	switch value := value.(type) {
	case string:
		a1, err := decode(value)
		if err != nil {
			return err
		}

		*a = a1

		return nil
	default:
		return xerrors.New("non-string types unsupported")
	}
}

// NewIDAddress returns an address using the ID protocol.
func NewIDAddress(id uint64) (Address, error) {
	if id > math.MaxInt64 {
		return Undef, xerrors.New("IDs must be less than 2^63")
	}
	return newAddress(ID, varint.ToUvarint(id))
}

// NewSecp256k1Address returns an address using the SECP256K1 protocol.
func NewSecp256k1Address(pubkey []byte) (Address, error) {
	return newAddress(SECP256K1, addressHash(pubkey))
}

// NewActorAddress returns an address using the Actor protocol.
func NewActorAddress(data []byte) (Address, error) {
	return newAddress(Actor, addressHash(data))
}

// NewBLSAddress returns an address using the BLS protocol.
func NewBLSAddress(pubkey []byte) (Address, error) {
	return newAddress(BLS, pubkey)
}

// NewDelegatedAddress returns an address using the Delegated protocol.
func NewDelegatedAddress(namespace uint64, subaddr []byte) (Address, error) {
	if namespace > math.MaxInt64 {
		return Undef, xerrors.New("namespace must be less than 2^63")
	}
	if len(subaddr) > MaxSubaddressLen {
		return Undef, ErrInvalidLength
	}

	payload := append(varint.ToUvarint(namespace), subaddr...)
	return newAddress(Delegated, payload)
}

// NewFromString returns the address represented by the string `addr`.
func NewFromString(addr string) (Address, error) {
	return decode(addr)
}

// NewFromBytes return the address represented by the bytes `addr`.
func NewFromBytes(addr []byte) (Address, error) {
	if len(addr) == 0 {
		return Undef, nil
	}
	if len(addr) == 1 {
		return Undef, ErrInvalidLength
	}
	return newAddress(addr[0], addr[1:])
}

// Checksum returns the checksum of `ingest`.
func Checksum(ingest []byte) []byte {
	return hash(ingest, ChecksumHashLength)
}

// ValidateChecksum returns true if the checksum of `ingest` is equal to `expected`>
func ValidateChecksum(ingest, expect []byte) bool {
	digest := Checksum(ingest)
	return bytes.Equal(digest, expect)
}

func addressHash(ingest []byte) []byte {
	return hash(ingest, PayloadHashLength)
}

// FIXME: This needs to be unified with the logic of `decode` (which would
//
//	handle the initial verification of the checksum separately), both are doing
//	the exact same length checks.
func newAddress(protocol Protocol, payload []byte) (Address, error) {
	switch protocol {
	case ID:
		v, n, err := varint.FromUvarint(payload)
		if err != nil {
			return Undef, xerrors.Errorf("could not decode: %v: %w", err, ErrInvalidPayload)
		}
		if n != len(payload) {
			return Undef, xerrors.Errorf("different varint length (v:%d != p:%d): %w",
				n, len(payload), ErrInvalidLength)
		}
		if v > math.MaxInt64 {
			return Undef, xerrors.Errorf("id addresses must be less than 2^63: %w", ErrInvalidPayload)
		}
	case SECP256K1, Actor:
		if len(payload) != PayloadHashLength {
			return Undef, ErrInvalidLength
		}
	case BLS:
		if len(payload) != BlsPublicKeyBytes {
			return Undef, ErrInvalidLength
		}
	case Delegated:
		namespace, n, err := varint.FromUvarint(payload)
		if err != nil {
			return Undef, xerrors.Errorf("could not decode delegated address namespace: %v: %w", err, ErrInvalidPayload)
		}
		if namespace > math.MaxInt64 {
			return Undef, xerrors.Errorf("namespace id must be less than 2^63: %w", ErrInvalidPayload)
		}
		if len(payload)-n > MaxSubaddressLen {
			return Undef, ErrInvalidLength
		}
	default:
		return Undef, ErrUnknownProtocol
	}
	explen := 1 + len(payload)
	buf := make([]byte, explen)

	buf[0] = protocol
	copy(buf[1:], payload)

	return Address{string(buf)}, nil
}

func encode(network Network, addr Address) (string, error) {
	if addr == Undef {
		return UndefAddressString, nil
	}
	var ntwk string
	switch network {
	case Mainnet:
		ntwk = MainnetPrefix
	case Testnet:
		ntwk = TestnetPrefix
	default:
		return UndefAddressString, ErrUnknownNetwork
	}

	protocol := addr.Protocol()
	payload := addr.Payload()
	var strAddr string
	switch protocol {
	case SECP256K1, Actor, BLS, Delegated:
		// The checksum and prefix is the same for all protocols
		cksm := Checksum(append([]byte{protocol}, payload...))
		strAddr = ntwk + fmt.Sprintf("%d", protocol)

		// if delegated, we need to write the namespace out separately.
		if protocol == Delegated {
			namespace, n, err := varint.FromUvarint(payload)
			if err != nil {
				return UndefAddressString, xerrors.Errorf("could not decode delegated address namespace: %w", err)
			}
			payload = payload[n:]
			strAddr += fmt.Sprintf("%df", namespace)
		}

		// Then encode the payload (or the rest of it) and the checksum.
		strAddr += AddressEncoding.WithPadding(-1).EncodeToString(append(payload, cksm[:]...))
	case ID:
		i, n, err := varint.FromUvarint(payload)
		if err != nil {
			return UndefAddressString, xerrors.Errorf("could not decode varint: %w", err)
		}
		if n != len(payload) {
			return UndefAddressString, xerrors.Errorf("payload contains additional bytes")
		}
		strAddr = fmt.Sprintf("%s%d%d", ntwk, addr.Protocol(), i)
	default:
		return UndefAddressString, ErrUnknownProtocol
	}
	return strAddr, nil
}

func base32decode(s string) ([]byte, error) {
	decoded, err := AddressEncoding.WithPadding(-1).DecodeString(s)
	if err != nil {
		return nil, err
	}

	reencoded := AddressEncoding.WithPadding(-1).EncodeToString(decoded)
	if reencoded != s {
		return nil, ErrInvalidEncoding
	}
	return decoded, nil
}

func decode(a string) (Address, error) {
	if len(a) == 0 {
		return Undef, nil
	}
	if a == UndefAddressString {
		return Undef, nil
	}
	if len(a) > MaxAddressStringLength || len(a) < 3 {
		return Undef, ErrInvalidLength
	}

	if string(a[0]) != MainnetPrefix && string(a[0]) != TestnetPrefix {
		return Undef, ErrUnknownNetwork
	}

	var protocol Protocol
	switch a[1] {
	case '0':
		protocol = ID
	case '1':
		protocol = SECP256K1
	case '2':
		protocol = Actor
	case '3':
		protocol = BLS
	case '4':
		protocol = Delegated
	default:
		return Undef, ErrUnknownProtocol
	}

	raw := a[2:]
	if protocol == ID {
		if len(raw) > MaxInt64StringLength {
			return Undef, ErrInvalidLength
		}
		id, err := strconv.ParseUint(raw, 10, 63)
		if err != nil {
			return Undef, ErrInvalidPayload
		}
		return newAddress(protocol, varint.ToUvarint(id))
	}

	var cksum, payload []byte
	if protocol == Delegated {
		parts := strings.SplitN(raw, "f", 2)
		if len(parts) != 2 {
			return Undef, ErrInvalidPayload
		}
		namespaceStr := parts[0]
		subaddrStr := parts[1]

		if len(namespaceStr) > MaxInt64StringLength {
			return Undef, ErrInvalidLength
		}
		namespace, err := strconv.ParseUint(namespaceStr, 10, 63)
		if err != nil {
			return Undef, ErrInvalidPayload
		}

		subaddrcksm, err := base32decode(subaddrStr)
		if err != nil {
			return Undef, err
		}

		if len(subaddrcksm) < ChecksumHashLength {
			return Undef, ErrInvalidLength
		}
		subaddr := subaddrcksm[:len(subaddrcksm)-ChecksumHashLength]
		cksum = subaddrcksm[len(subaddrcksm)-ChecksumHashLength:]
		if len(subaddr) > MaxSubaddressLen {
			return Undef, ErrInvalidLength
		}

		payload = append(varint.ToUvarint(namespace), subaddr...)
	} else {
		payloadcksm, err := base32decode(raw)
		if err != nil {
			return Undef, err
		}

		if len(payloadcksm) < ChecksumHashLength {
			return Undef, ErrInvalidLength
		}

		payload = payloadcksm[:len(payloadcksm)-ChecksumHashLength]
		cksum = payloadcksm[len(payloadcksm)-ChecksumHashLength:]

		if protocol == SECP256K1 || protocol == Actor {
			if len(payload) != PayloadHashLength {
				return Undef, ErrInvalidLength
			}
		}

		if protocol == BLS {
			if len(payload) != BlsPublicKeyBytes {
				return Undef, ErrInvalidLength
			}
		}
	}

	if !ValidateChecksum(append([]byte{protocol}, payload...), cksum) {
		return Undef, ErrInvalidChecksum
	}

	return newAddress(protocol, payload)
}

// hash returns the BLAKE2b checksum using a hasher of custom length size
func hash(ingest []byte, size int) []byte {
	hasher, err := blake2b.New(size, nil)
	if err != nil {
		// If this happens sth is very wrong.
		panic(fmt.Sprintf("invalid address hash configuration: %v", err)) // ok
	}
	if _, err := hasher.Write(ingest); err != nil {
		// blake2bs Write implementation never returns an error in its current
		// setup. So if this happens sth went very wrong.
		panic(fmt.Sprintf("blake2b is unable to process hashes: %v", err)) // ok
	}
	return hasher.Sum(nil)
}

func (a Address) MarshalBinary() ([]byte, error) {
	return a.Bytes(), nil
}

func (a *Address) UnmarshalBinary(b []byte) error {
	newAddr, err := NewFromBytes(b)
	if err != nil {
		return err
	}
	*a = newAddr
	return nil
}

func (a *Address) MarshalCBOR(w io.Writer) error {
	if a == nil {
		_, err := w.Write(cbg.CborNull)
		return err
	}

	if *a == Undef {
		return fmt.Errorf("cannot marshal undefined address")
	}

	if err := cbg.WriteMajorTypeHeader(w, cbg.MajByteString, uint64(len(a.str))); err != nil {
		return err
	}

	if _, err := io.WriteString(w, a.str); err != nil {
		return err
	}

	return nil
}

func (a *Address) UnmarshalCBOR(r io.Reader) error {
	br := cbg.GetPeeker(r)

	maj, extra, err := cbg.CborReadHeader(br)
	if err != nil {
		return err
	}

	if maj != cbg.MajByteString {
		return fmt.Errorf("cbor type for address unmarshal was not byte string")
	}

	if extra > 64 {
		return fmt.Errorf("too many bytes to unmarshal for an address")
	}

	buf := make([]byte, int(extra))
	if _, err := io.ReadFull(br, buf); err != nil {
		return err
	}

	addr, err := NewFromBytes(buf)
	if err != nil {
		return err
	}
	if addr == Undef {
		return fmt.Errorf("cbor input should not contain empty addresses")
	}

	*a = addr

	return nil
}

func IDFromAddress(addr Address) (uint64, error) {
	if addr.Protocol() != ID {
		return 0, xerrors.Errorf("cannot get id from non id address")
	}

	i, _, err := varint.FromUvarint(addr.Payload())
	return i, err
}
