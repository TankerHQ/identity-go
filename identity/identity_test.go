package identity

import (
	"crypto/rand"
	"encoding/base64"

	"golang.org/x/crypto/ed25519"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func checkDelegationSignature(identity identity, trustchainPublicKey []byte) {
	obfuscatedUserID, _ := base64.StdEncoding.DecodeString(identity.Value)
	signedData := append(
		identity.EphemeralPublicSignatureKey,
		obfuscatedUserID...)

	Expect(ed25519.Verify(
		trustchainPublicKey,
		signedData,
		identity.DelegationSignature,
	)).To(Equal(true))
}

var _ = Describe("generateIdentity", func() {
	var (
		trustchainPublicKey  []byte
		trustchainPrivateKey []byte
		trustchainID         []byte
		conf                 config
		userID               = "userID"
		obfuscatedUserID     []byte
	)

	BeforeEach(func() {
		trustchainPublicKey, trustchainPrivateKey, _ = ed25519.GenerateKey(nil)
		trustchainID = make([]byte, 32)
		_, _ = rand.Read(trustchainID)
		obfuscatedUserID = hashUserID(trustchainID, userID)
		conf = config{
			TrustchainID:         trustchainID,
			TrustchainPrivateKey: trustchainPrivateKey,
		}
	})

	It("generateIdentity returns a valid tanker identity", func() {
		identity, err := generateIdentity(conf, userID)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(identity.TrustchainID).To(Equal(trustchainID))
		Expect(identity.Target).To(Equal("user"))
		Expect(identity.Value).To(Equal(base64.StdEncoding.EncodeToString(obfuscatedUserID)))
		checkDelegationSignature(*identity, trustchainPublicKey)
	})

	It("generateProvisionalIdentity returns a valid tanker provisional identity", func() {
		provisionalIdentity, err := generateProvisionalIdentity(conf, "email@example.com")
		Expect(err).ShouldNot(HaveOccurred())

		Expect(provisionalIdentity.TrustchainID).To(Equal(trustchainID))
		Expect(provisionalIdentity.Target).To(Equal("email"))
		Expect(provisionalIdentity.Value).To(Equal("email@example.com"))
	})
})
