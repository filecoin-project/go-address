package address

import (
	"bytes"
	"encoding/base32"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"strconv"
	"strings"
	"testing"

	"github.com/multiformats/go-varint"
	"github.com/stretchr/testify/assert"
	"golang.org/x/xerrors"

	cbg "github.com/whyrusleeping/cbor-gen"
)

func TestRandomIDAddress(t *testing.T) {
	assert := assert.New(t)

	addr, err := NewIDAddress(uint64(rand.Int()))
	assert.NoError(err)
	assert.Equal(ID, addr.Protocol())

	str, err := encode(Testnet, addr)
	assert.NoError(err)

	maybe, err := decode(str)
	assert.NoError(err)
	assert.Equal(addr, maybe)

}

var allTestAddresses = []string{
	"t00",
	"t01",
	"t010",
	"t0150",
	"t0499",
	"t01024",
	"t01729",
	"t0999999",
	"t15ihq5ibzwki2b4ep2f46avlkrqzhpqgtga7pdrq",
	"t12fiakbhe2gwd5cnmrenekasyn6v5tnaxaqizq6a",
	"t1wbxhu3ypkuo6eyp6hjx6davuelxaxrvwb2kuwva",
	"t1xtwapqc6nh4si2hcwpr3656iotzmlwumogqbuaa",
	"t1xcbgdhkgkwht3hrrnui3jdopeejsoatkzmoltqy",
	"t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
	"t24vg6ut43yw2h2jqydgbg2xq7x6f4kub3bg6as6i",
	"t25nml2cfbljvn4goqtclhifepvfnicv6g7mfmmvq",
	"t2nuqrg7vuysaue2pistjjnt3fadsdzvyuatqtfei",
	"t24dd4ox4c2vpf5vk5wkadgyyn6qtuvgcpxxon64a",
	"t2gfvuyh7v2sx3patm5k23wdzmhyhtmqctasbr23y",
	"t3vvmn62lofvhjd2ugzca6sof2j2ubwok6cj4xxbfzz4yuxfkgobpihhd2thlanmsh3w2ptld2gqkn2jvlss4a",
	"t3wmuu6crofhqmm3v4enos73okk2l366ck6yc4owxwbdtkmpk42ohkqxfitcpa57pjdcftql4tojda2poeruwa",
	"t3s2q2hzhkpiknjgmf4zq3ejab2rh62qbndueslmsdzervrhapxr7dftie4kpnpdiv2n6tvkr743ndhrsw6d3a",
	"t3q22fijmmlckhl56rn5nkyamkph3mcfu5ed6dheq53c244hfmnq2i7efdma3cj5voxenwiummf2ajlsbxc65a",
	"t3u5zgwa4ael3vuocgc5mfgygo4yuqocrntuuhcklf4xzg5tcaqwbyfabxetwtj4tsam3pbhnwghyhijr5mixa",
}

func TestVectorsIDAddress(t *testing.T) {
	testCases := []struct {
		input    uint64
		expected string
	}{
		{uint64(0), "t00"},
		{uint64(1), "t01"},
		{uint64(10), "t010"},
		{uint64(150), "t0150"},
		{uint64(499), "t0499"},
		{uint64(1024), "t01024"},
		{uint64(1729), "t01729"},
		{uint64(999999), "t0999999"},
		{math.MaxInt64, fmt.Sprintf("t0%s", strconv.FormatUint(math.MaxInt64, 10))},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(fmt.Sprintf("testing actorID address: %s", tc.expected), func(t *testing.T) {
			assert := assert.New(t)

			// Round trip encoding and decoding from string
			CurrentNetwork = Testnet
			addr, err := NewIDAddress(tc.input)
			assert.NoError(err)

			validateAddress(t, addr, varint.ToUvarint(tc.input), tc.expected)
		})
	}

}

func TestVectorSecp256k1Address(t *testing.T) {
	testCases := []struct {
		input                  []byte
		expectedTestnetAddrStr string
		expectedMainnetAddrStr string
	}{
		{[]byte{4, 148, 2, 250, 195, 126, 100, 50, 164, 22, 163, 160, 202, 84,
			38, 181, 24, 90, 179, 178, 79, 97, 52, 239, 162, 92, 228, 135, 200,
			45, 46, 78, 19, 191, 69, 37, 17, 224, 210, 36, 84, 33, 248, 97, 59,
			193, 13, 114, 250, 33, 102, 102, 169, 108, 59, 193, 57, 32, 211,
			255, 35, 63, 208, 188, 5},
			"t15ihq5ibzwki2b4ep2f46avlkrqzhpqgtga7pdrq",
			"f15ihq5ibzwki2b4ep2f46avlkrqzhpqgtga7pdrq",
		},

		{[]byte{4, 118, 135, 185, 16, 55, 155, 242, 140, 190, 58, 234, 103, 75,
			18, 0, 12, 107, 125, 186, 70, 255, 192, 95, 108, 148, 254, 42, 34,
			187, 204, 38, 2, 255, 127, 92, 118, 242, 28, 165, 93, 54, 149, 145,
			82, 176, 225, 232, 135, 145, 124, 57, 53, 118, 238, 240, 147, 246,
			30, 189, 58, 208, 111, 127, 218},
			"t12fiakbhe2gwd5cnmrenekasyn6v5tnaxaqizq6a",
			"f12fiakbhe2gwd5cnmrenekasyn6v5tnaxaqizq6a",
		},
		{[]byte{4, 222, 253, 208, 16, 1, 239, 184, 110, 1, 222, 213, 206, 52,
			248, 71, 167, 58, 20, 129, 158, 230, 65, 188, 182, 11, 185, 41, 147,
			89, 111, 5, 220, 45, 96, 95, 41, 133, 248, 209, 37, 129, 45, 172,
			65, 99, 163, 150, 52, 155, 35, 193, 28, 194, 255, 53, 157, 229, 75,
			226, 135, 234, 98, 49, 155},
			"t1wbxhu3ypkuo6eyp6hjx6davuelxaxrvwb2kuwva",
			"f1wbxhu3ypkuo6eyp6hjx6davuelxaxrvwb2kuwva",
		},
		{[]byte{4, 3, 237, 18, 200, 20, 182, 177, 13, 46, 224, 157, 149, 180,
			104, 141, 178, 209, 128, 208, 169, 163, 122, 107, 106, 125, 182, 61,
			41, 129, 30, 233, 115, 4, 121, 216, 239, 145, 57, 233, 18, 73, 202,
			189, 57, 50, 145, 207, 229, 210, 119, 186, 118, 222, 69, 227, 224,
			133, 163, 118, 129, 191, 54, 69, 210},
			"t1xtwapqc6nh4si2hcwpr3656iotzmlwumogqbuaa",
			"f1xtwapqc6nh4si2hcwpr3656iotzmlwumogqbuaa",
		},
		{[]byte{4, 247, 150, 129, 154, 142, 39, 22, 49, 175, 124, 24, 151, 151,
			181, 69, 214, 2, 37, 147, 97, 71, 230, 1, 14, 101, 98, 179, 206, 158,
			254, 139, 16, 20, 65, 97, 169, 30, 208, 180, 236, 137, 8, 0, 37, 63,
			166, 252, 32, 172, 144, 251, 241, 251, 242, 113, 48, 164, 236, 195,
			228, 3, 183, 5, 118},
			"t1xcbgdhkgkwht3hrrnui3jdopeejsoatkzmoltqy",
			"f1xcbgdhkgkwht3hrrnui3jdopeejsoatkzmoltqy",
		},
		{[]byte{4, 66, 131, 43, 248, 124, 206, 158, 163, 69, 185, 3, 80, 222,
			125, 52, 149, 133, 156, 164, 73, 5, 156, 94, 136, 221, 231, 66, 133,
			223, 251, 158, 192, 30, 186, 188, 95, 200, 98, 104, 207, 234, 235,
			167, 174, 5, 191, 184, 214, 142, 183, 90, 82, 104, 120, 44, 248, 111,
			200, 112, 43, 239, 138, 31, 224},
			"t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
			"f17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
		},
	}

	for _, tc := range testCases {
		tc := tc
		name := fmt.Sprintf(
			"testing secp256k1 address: %s (testnet), %s (mainnet)",
			tc.expectedTestnetAddrStr,
			tc.expectedMainnetAddrStr,
		)
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			// Testnet
			// Round trip encoding and decoding from string
			CurrentNetwork = Testnet
			addr, err := NewSecp256k1Address(tc.input)
			assert.NoError(err)
			validateAddress(t, addr, addressHash(tc.input), tc.expectedTestnetAddrStr)

			// Mainnet
			// Round trip encoding and decoding from string
			CurrentNetwork = Mainnet
			validateAddress(t, addr, addressHash(tc.input), tc.expectedMainnetAddrStr)
		})
	}
}

func TestRandomActorAddress(t *testing.T) {
	assert := assert.New(t)

	actorMsg := make([]byte, 20)
	//lint:ignore SA1019 we want non-crypto randomness
	rand.Read(actorMsg)

	addr, err := NewActorAddress(actorMsg)
	assert.NoError(err)
	assert.Equal(Actor, addr.Protocol())

	str, err := encode(Mainnet, addr)
	assert.NoError(err)

	maybe, err := decode(str)
	assert.NoError(err)
	assert.Equal(addr, maybe)
}

func TestVectorActorAddress(t *testing.T) {
	testCases := []struct {
		input                  []byte
		expectedTestnetAddrStr string
		expectedMainnetAddrStr string
	}{
		{[]byte{118, 18, 129, 144, 205, 240, 104, 209, 65, 128, 68, 172, 192,
			62, 11, 103, 129, 151, 13, 96},
			"t24vg6ut43yw2h2jqydgbg2xq7x6f4kub3bg6as6i",
			"f24vg6ut43yw2h2jqydgbg2xq7x6f4kub3bg6as6i",
		},
		{[]byte{44, 175, 184, 226, 224, 107, 186, 152, 234, 101, 124, 92, 245,
			244, 32, 35, 170, 35, 232, 142},
			"t25nml2cfbljvn4goqtclhifepvfnicv6g7mfmmvq",
			"f25nml2cfbljvn4goqtclhifepvfnicv6g7mfmmvq",
		},
		{[]byte{2, 44, 158, 14, 162, 157, 143, 64, 197, 106, 190, 195, 92, 141,
			88, 125, 160, 166, 76, 24},
			"t2nuqrg7vuysaue2pistjjnt3fadsdzvyuatqtfei",
			"f2nuqrg7vuysaue2pistjjnt3fadsdzvyuatqtfei",
		},
		{[]byte{223, 236, 3, 14, 32, 79, 15, 89, 216, 15, 29, 94, 233, 29, 253,
			6, 109, 127, 99, 189},
			"t24dd4ox4c2vpf5vk5wkadgyyn6qtuvgcpxxon64a",
			"f24dd4ox4c2vpf5vk5wkadgyyn6qtuvgcpxxon64a",
		},
		{[]byte{61, 58, 137, 232, 221, 171, 84, 120, 50, 113, 108, 109, 70, 140,
			53, 96, 201, 244, 127, 216},
			"t2gfvuyh7v2sx3patm5k23wdzmhyhtmqctasbr23y",
			"f2gfvuyh7v2sx3patm5k23wdzmhyhtmqctasbr23y",
		},
	}

	for _, tc := range testCases {
		tc := tc
		name := fmt.Sprintf(
			"testing Actor address: %s (testnet), %s (mainnet)",
			tc.expectedTestnetAddrStr,
			tc.expectedMainnetAddrStr,
		)
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			// Testnet
			// Round trip encoding and decoding from string
			CurrentNetwork = Testnet
			addr, err := NewActorAddress(tc.input)
			assert.NoError(err)

			validateAddress(t, addr, addressHash(tc.input), tc.expectedTestnetAddrStr)

			// Mainnet
			// Round trip encoding and decoding from string
			CurrentNetwork = Mainnet
			validateAddress(t, addr, addressHash(tc.input), tc.expectedMainnetAddrStr)
		})
	}
}

func validateAddress(t *testing.T, addr Address, expectedPayload []byte, expectedString string) {
	t.Helper()
	assert := assert.New(t)

	assert.Equal(expectedString, addr.String())

	// Round trip from the string.
	parsed, err := NewFromString(expectedString)
	assert.NoError(err)
	assert.Equal(addr.Protocol(), parsed.Protocol())
	assert.Equal(expectedPayload, parsed.Payload())
	assert.Equal(addr.Payload(), parsed.Payload())

	// Round trip to and from bytes from the string.
	fromBytes, err := NewFromBytes(parsed.Bytes())
	assert.NoError(err)
	assert.Equal(parsed, fromBytes)

	// Round trip encoding and decoding json
	mb, err := addr.MarshalJSON()
	assert.NoError(err)

	var parsedJson Address
	err = parsedJson.UnmarshalJSON(mb)
	assert.NoError(err)
	assert.Equal(addr, parsedJson)
}

func TestVectorBLSAddress(t *testing.T) {
	testCases := []struct {
		input                  []byte
		expectedTestnetAddrStr string
		expectedMainnetAddrStr string
	}{
		{[]byte{173, 88, 223, 105, 110, 45, 78, 145, 234, 134, 200, 129, 233, 56,
			186, 78, 168, 27, 57, 94, 18, 121, 123, 132, 185, 207, 49, 75, 149, 70,
			112, 94, 131, 156, 122, 153, 214, 6, 178, 71, 221, 180, 249, 172, 122,
			52, 20, 221},
			"t3vvmn62lofvhjd2ugzca6sof2j2ubwok6cj4xxbfzz4yuxfkgobpihhd2thlanmsh3w2ptld2gqkn2jvlss4a",
			"f3vvmn62lofvhjd2ugzca6sof2j2ubwok6cj4xxbfzz4yuxfkgobpihhd2thlanmsh3w2ptld2gqkn2jvlss4a",
		},
		{[]byte{179, 41, 79, 10, 46, 41, 224, 198, 110, 188, 35, 93, 47, 237,
			202, 86, 151, 191, 120, 74, 246, 5, 199, 90, 246, 8, 230, 166, 61, 92,
			211, 142, 168, 92, 168, 152, 158, 14, 253, 233, 24, 139, 56, 47,
			147, 114, 70, 13},
			"t3wmuu6crofhqmm3v4enos73okk2l366ck6yc4owxwbdtkmpk42ohkqxfitcpa57pjdcftql4tojda2poeruwa",
			"f3wmuu6crofhqmm3v4enos73okk2l366ck6yc4owxwbdtkmpk42ohkqxfitcpa57pjdcftql4tojda2poeruwa",
		},
		{[]byte{150, 161, 163, 228, 234, 122, 20, 212, 153, 133, 230, 97, 178,
			36, 1, 212, 79, 237, 64, 45, 29, 9, 37, 178, 67, 201, 35, 88, 156,
			15, 188, 126, 50, 205, 4, 226, 158, 215, 141, 21, 211, 125, 58, 170,
			63, 230, 218, 51},
			"t3s2q2hzhkpiknjgmf4zq3ejab2rh62qbndueslmsdzervrhapxr7dftie4kpnpdiv2n6tvkr743ndhrsw6d3a",
			"f3s2q2hzhkpiknjgmf4zq3ejab2rh62qbndueslmsdzervrhapxr7dftie4kpnpdiv2n6tvkr743ndhrsw6d3a",
		},
		{[]byte{134, 180, 84, 37, 140, 88, 148, 117, 247, 209, 111, 90, 172, 1,
			138, 121, 246, 193, 22, 157, 32, 252, 51, 146, 29, 216, 181, 206, 28,
			172, 108, 52, 143, 144, 163, 96, 54, 36, 246, 174, 185, 27, 100, 81,
			140, 46, 128, 149},
			"t3q22fijmmlckhl56rn5nkyamkph3mcfu5ed6dheq53c244hfmnq2i7efdma3cj5voxenwiummf2ajlsbxc65a",
			"f3q22fijmmlckhl56rn5nkyamkph3mcfu5ed6dheq53c244hfmnq2i7efdma3cj5voxenwiummf2ajlsbxc65a",
		},
		{[]byte{167, 114, 107, 3, 128, 34, 247, 90, 56, 70, 23, 88, 83, 96, 206,
			230, 41, 7, 10, 45, 157, 40, 113, 41, 101, 229, 242, 110, 204, 64,
			133, 131, 130, 128, 55, 36, 237, 52, 242, 114, 3, 54, 240, 157, 182,
			49, 240, 116},
			"t3u5zgwa4ael3vuocgc5mfgygo4yuqocrntuuhcklf4xzg5tcaqwbyfabxetwtj4tsam3pbhnwghyhijr5mixa",
			"f3u5zgwa4ael3vuocgc5mfgygo4yuqocrntuuhcklf4xzg5tcaqwbyfabxetwtj4tsam3pbhnwghyhijr5mixa",
		},
	}

	for _, tc := range testCases {
		tc := tc
		name := fmt.Sprintf(
			"testing bls address: %s (testnet), %s (mainnet)",
			tc.expectedTestnetAddrStr,
			tc.expectedMainnetAddrStr,
		)
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			// Testnet
			// Round trip encoding and decoding from string
			CurrentNetwork = Testnet
			addr, err := NewBLSAddress(tc.input)
			assert.NoError(err)
			assert.Equal(tc.expectedTestnetAddrStr, addr.String())

			maybeTestnetAddr, err := NewFromString(tc.expectedTestnetAddrStr)
			assert.NoError(err)
			assert.Equal(BLS, maybeTestnetAddr.Protocol())
			assert.Equal(tc.input, maybeTestnetAddr.Payload())

			// Round trip to and from bytes
			maybeTestnetAddrBytes, err := NewFromBytes(maybeTestnetAddr.Bytes())
			assert.NoError(err)
			assert.Equal(maybeTestnetAddr, maybeTestnetAddrBytes)

			// Round trip encoding and decoding json
			tb, err := addr.MarshalJSON()
			assert.NoError(err)

			var newTestnetAddr Address
			err = newTestnetAddr.UnmarshalJSON(tb)
			assert.NoError(err)
			assert.Equal(addr, newTestnetAddr)

			// Mainnet
			// Round trip encoding and decoding from string
			CurrentNetwork = Mainnet
			assert.Equal(tc.expectedMainnetAddrStr, addr.String())

			maybeMainnetAddr, err := NewFromString(tc.expectedMainnetAddrStr)
			assert.NoError(err)
			assert.Equal(BLS, maybeMainnetAddr.Protocol())
			assert.Equal(tc.input, maybeMainnetAddr.Payload())

			// Round trip to and from bytes
			maybeMainnetAddrBytes, err := NewFromBytes(maybeMainnetAddr.Bytes())
			assert.NoError(err)
			assert.Equal(maybeMainnetAddr, maybeMainnetAddrBytes)

			// Round trip encoding and decoding json
			mb, err := addr.MarshalJSON()
			assert.NoError(err)

			var newMainnetAddr Address
			err = newMainnetAddr.UnmarshalJSON(mb)
			assert.NoError(err)
			assert.Equal(addr, newMainnetAddr)
		})
	}
}

// FIXME: Do not hardcode network and protocol values.
func TestInvalidStringAddresses(t *testing.T) {
	idPayloadMaxLength := MaxInt64StringLength
	secpPayloadChecksumFixedLength := PayloadHashLength + ChecksumHashLength
	actorPayloadChecksumFixedLength := secpPayloadChecksumFixedLength
	blsPayloadChecksumFixedLength := BlsPublicKeyBytes + ChecksumHashLength

	testCases := []struct {
		input string
		// Complement input that needs to be encoded in base 32. This allows
		// to write the tests for non-ID addresses in plain format to make them
		// easier to follow.
		inputToEncode string
		expetErr      error
	}{
		{"Q2gfvuyh7v2sx3patm5k23wdzmhyhtmqctasbr23y", "", ErrUnknownNetwork},
		{"t5gfvuyh7v2sx3patm5k23wdzmhyhtmqctasbr23y", "", ErrUnknownProtocol},
		{"t2gfvuyh7v2sx3patm5k23wdzmhyhtmqctasbr24y", "", ErrInvalidChecksum},
		{"t0banananananannnnnnnnn", "", ErrInvalidLength},
		{"t0banananananannnnnnn", "", ErrInvalidPayload},
		{"t2gfvuyh7v2sx3patm1k23wdzmhyhtmqctasbr24y", "", base32.CorruptInputError(16)}, // '1' is not in base32 alphabet
		{"t2gfvuyh7v2sx3paTm1k23wdzmhyhtmqctasbr24y", "", base32.CorruptInputError(14)}, // 'T' is not in base32 alphabet
		{"t2", "", ErrInvalidLength},
		{"t1234q", "", ErrInvalidLength},
		{"Q2gfvuyh7v2sx3patm5k23wdzmhyhtmqctasbr23y", "", ErrUnknownNetwork},
		{"t5gfvuyh7v2sx3patm5k23wdzmhyhtmqctasbr23y", "", ErrUnknownProtocol},
		{"t2gfvuyh7v2sx3patm5k23wdzmhyhtmqctasbr24y", "", ErrInvalidChecksum},
		{strings.Repeat("a", MaxAddressStringLength+1), "", ErrInvalidLength},
		{"t", "", ErrInvalidLength},
		{"t0", "", ErrInvalidLength},
		// FIXME: The repetitions should be abstracted in the testing logic below
		//  (similar to what was done with `inputToEncode`).
		{"t0" + strings.Repeat("a", idPayloadMaxLength), "", ErrInvalidPayload},
		{"t0" + strings.Repeat("a", idPayloadMaxLength+1), "", ErrInvalidLength},
		{"t1", strings.Repeat("a", secpPayloadChecksumFixedLength), ErrInvalidChecksum},
		{"t1", strings.Repeat("a", secpPayloadChecksumFixedLength+1), ErrInvalidLength},
		{"t1", strings.Repeat("a", secpPayloadChecksumFixedLength-1), ErrInvalidLength},
		{"t2", strings.Repeat("a", actorPayloadChecksumFixedLength), ErrInvalidChecksum},
		{"t2", strings.Repeat("a", actorPayloadChecksumFixedLength+1), ErrInvalidLength},
		{"t2", strings.Repeat("a", actorPayloadChecksumFixedLength-1), ErrInvalidLength},
		{"t3", strings.Repeat("a", blsPayloadChecksumFixedLength), ErrInvalidChecksum},
		{"t3", strings.Repeat("a", blsPayloadChecksumFixedLength+1), ErrInvalidLength},
		{"t3", strings.Repeat("a", blsPayloadChecksumFixedLength-1), ErrInvalidLength},
		{"t2gfvuyh7v2sx3patm1k23wdzmhyhtmqctasbr24y", "", base32.CorruptInputError(16)}, // '1' is not in base32 alphabet
		{"t2gfvuyh7v2sx3paTm1k23wdzmhyhtmqctasbr24y", "", base32.CorruptInputError(14)}, // 'T' is not in base32 alphabet
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(fmt.Sprintf("testing string address: %s", tc.expetErr), func(t *testing.T) {
			assert := assert.New(t)

			encoded := ""
			if tc.inputToEncode != "" {
				encoded = AddressEncoding.WithPadding(-1).EncodeToString([]byte(tc.inputToEncode))
			}
			_, err := NewFromString(tc.input + encoded)
			assert.Equal(tc.expetErr, err)
		})
	}

}

func TestInvalidByteAddresses(t *testing.T) {
	testCases := []struct {
		input     []byte
		expectErr error
	}{
		// Unknown Protocol
		{[]byte{5, 4, 4}, ErrUnknownProtocol},

		// ID protocol
		{[]byte{0}, ErrInvalidLength},

		// SECP256K1 Protocol
		{append([]byte{1}, make([]byte, PayloadHashLength-1)...), ErrInvalidLength},
		{append([]byte{1}, make([]byte, PayloadHashLength+1)...), ErrInvalidLength},

		// Actor Protocol
		{append([]byte{2}, make([]byte, PayloadHashLength-1)...), ErrInvalidLength},
		{append([]byte{2}, make([]byte, PayloadHashLength+1)...), ErrInvalidLength},

		// BLS Protocol
		{append([]byte{3}, make([]byte, BlsPublicKeyBytes-1)...), ErrInvalidLength},
		{append([]byte{3}, make([]byte, BlsPrivateKeyBytes+1)...), ErrInvalidLength},

		// Delegate Protocol
		// - subaddress exceeds the limit
		{append([]byte{4, 0}, make([]byte, MaxSubaddressLen+1)...), ErrInvalidLength},
		// - a hanging uvarint for a namespace
		{[]byte{4, 0xff}, ErrInvalidPayload},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(fmt.Sprintf("testing byte address: %s", tc.expectErr), func(t *testing.T) {
			assert := assert.New(t)

			_, err := NewFromBytes(tc.input)
			assert.True(xerrors.Is(err, tc.expectErr))
		})
	}

}

func TestChecksum(t *testing.T) {
	assert := assert.New(t)

	data := []byte("helloworld")
	bata := []byte("kittinmittins")

	cksm := Checksum(data)
	assert.Len(cksm, ChecksumHashLength)

	assert.True(ValidateChecksum(data, cksm))
	assert.False(ValidateChecksum(bata, cksm))

}

func TestCborMarshal(t *testing.T) {
	for _, a := range allTestAddresses {
		addr, err := NewFromString(a)
		if err != nil {
			t.Fatal(err)
		}

		buf := new(bytes.Buffer)
		if err := addr.MarshalCBOR(buf); err != nil {
			t.Fatal(err)
		}

		/*
			// Note: this is commented out because we're currently serializing addresses as cbor "text strings", not "byte strings".
			// This is to get around the restriction that refmt only allows string keys in maps.
			// if you change it to serialize to byte strings and uncomment this, the tests pass fine
			oldbytes, err := cbor.DumpObject(addr)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(oldbytes, buf.Bytes()) {
				t.Fatalf("serialization doesnt match old serialization: %s", a)
			}
		*/

		var out Address
		if err := out.UnmarshalCBOR(buf); err != nil {
			t.Fatal(err)
		}

		if out != addr {
			t.Fatalf("failed to round trip %s", a)
		}
	}
}

func TestCborMarshalNilAddress(t *testing.T) {
	var addr *Address
	buf := new(bytes.Buffer)
	if err := addr.MarshalCBOR(buf); err != nil {
		t.Fatal(err)
	}

	if string(cbg.CborNull) != buf.String() {
		t.Fatal("expected null")
	}
}

func BenchmarkCborMarshal(b *testing.B) {
	addr, err := NewFromString("t15ihq5ibzwki2b4ep2f46avlkrqzhpqgtga7pdrq")
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	buf := new(bytes.Buffer)
	for i := 0; i < b.N; i++ {
		buf.Reset()
		if err := addr.MarshalCBOR(buf); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCborUnmarshal(b *testing.B) {
	addr, err := NewFromString("t15ihq5ibzwki2b4ep2f46avlkrqzhpqgtga7pdrq")
	if err != nil {
		b.Fatal(err)
	}

	buf := new(bytes.Buffer)
	if err := addr.MarshalCBOR(buf); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		var a Address
		if err := a.UnmarshalCBOR(bytes.NewReader(buf.Bytes())); err != nil {
			b.Fatal(err)
		}
	}
}

func TestIDEdgeCase(t *testing.T) {
	a, err := NewFromBytes([]byte{0, 0x80})
	_ = a.String()
	assert.Error(t, err)
}

func TestIDMax(t *testing.T) {
	// Check construction.
	_, err := NewIDAddress(math.MaxInt64 + 1)
	assert.Error(t, err)
	a, err := NewIDAddress(math.MaxInt64)
	assert.NoError(t, err)

	// Check addr parsing.
	id, err := IDFromAddress(a)
	assert.NoError(t, err)
	assert.EqualValues(t, uint64(math.MaxInt64), id)

	// Check string parsing.
	_, err = NewFromString(fmt.Sprintf("t0%s", strconv.FormatUint(math.MaxInt64, 10)))
	assert.NoError(t, err)

	_, err = NewFromString(fmt.Sprintf("t0%s", strconv.FormatUint(math.MaxInt64+1, 10)))
	assert.Error(t, err)

	// Check CBOR unmarshaling.
	badAddr := Address{str: string([]byte{
		// 2**64 uvarint. We shouldn't be able to parse this.
		0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01,
	})}
	var buf bytes.Buffer
	err = badAddr.MarshalCBOR(&buf)
	assert.NoError(t, err)
	var targetAddr Address
	err = targetAddr.UnmarshalCBOR(&buf)
	assert.True(t, errors.Is(err, ErrInvalidPayload), "%#v", err)
}

func TestTrailingBits(t *testing.T) {
	goodStr := "f1xpbyy4tkdx5si2bgo37dubc2xwv6fum5tk57mia"
	badStr := "f1xpbyy4tkdx5si2bgo37dubc2xwv6fum5tk57mid"

	_, err := NewFromString(goodStr)
	assert.NoError(t, err, "should be able to decode the good string")

	_, err = NewFromString(badStr)
	assert.True(t, errors.Is(err, ErrInvalidEncoding), "%#v", err)
}

func TestDelegatedAddress(t *testing.T) {
	cases := []struct {
		namespace  uint64
		subaddress []byte
		expected   string
	}{
		{32, []byte{0xff, 0xff, 0xff, 0xff, 0xff}, "f432f77777777x32lpna"},
		{varint.MaxValueUvarint63, []byte{}, "f49223372036854775807fiic6zsy"},
		{varint.MaxValueUvarint63, make([]byte, MaxSubaddressLen), "f49223372036854775807faaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaahwgiuam"},
	}

	CurrentNetwork = Mainnet

	for _, tc := range cases {
		t.Run(fmt.Sprintf("delegated_%s", tc.expected), func(t *testing.T) {
			addr, err := NewDelegatedAddress(tc.namespace, tc.subaddress)
			assert.NoError(t, err)
			payload := append(varint.ToUvarint(tc.namespace), tc.subaddress...)
			validateAddress(t, addr, payload, tc.expected)
		})
	}
}
