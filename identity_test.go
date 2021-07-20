package identity

import (
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

var _ = Describe("newIdentity", func() {
	var (
		trustchainPublicKey []byte
		AppSecret           []byte
		AppID               []byte
		conf                config
		userID              = "userID"
		obfuscatedUserID    []byte
	)

	BeforeEach(func() {
		trustchainPublicKeyStr := "r6oz1Rpl3dsMGu8te0LT02YZ/G8W9NeQmQv3uGSO/jE="
		AppSecretStr := "cTMoGGUKhwN47ypq4xAXAtVkNWeyUtMltQnYwJhxWYSvqjPVGmXd2wwa7y17QtPTZhn8bxb015CZC/e4ZI7+MQ=="
		AppIDStr := "tpoxyNzh0hU9G2i9agMvHyyd+pO6zGCjO9BfhrCLjd4="

		trustchainPublicKey, _ = base64.StdEncoding.DecodeString(trustchainPublicKeyStr)
		AppSecret, _ = base64.StdEncoding.DecodeString(AppSecretStr)
		AppID, _ = base64.StdEncoding.DecodeString(AppIDStr)
		obfuscatedUserID = hashUserID(AppID, userID)
		conf = config{
			AppID:     AppID,
			AppSecret: AppSecret,
		}
	})

	It("newIdentity returns a valid tanker identity", func() {
		identity, err := newIdentity(conf, userID)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(identity.TrustchainID).To(Equal(AppID))
		Expect(identity.Target).To(Equal("user"))
		Expect(identity.Value).To(Equal(base64.StdEncoding.EncodeToString(obfuscatedUserID)))
		checkDelegationSignature(identity, trustchainPublicKey)
	})

	It("newProvisionalIdentity returns a valid tanker provisional identity", func() {
		provisionalIdentity, err := newProvisionalIdentity(conf, "email@example.com")
		Expect(err).ShouldNot(HaveOccurred())

		Expect(provisionalIdentity.TrustchainID).To(Equal(AppID))
		Expect(provisionalIdentity.Target).To(Equal("email"))
		Expect(provisionalIdentity.Value).To(Equal("email@example.com"))
	})

	It("returns an error if app ID and secret mismatch", func() {
		mismatchingAppIDStr := "rB0/yEJWCUVYRtDZLtXaJqtneXQOsCSKrtmWw+V+ysc="
		mismatchingAppID, _ := base64.StdEncoding.DecodeString(mismatchingAppIDStr)
		invalidConf := config{AppID: mismatchingAppID, AppSecret: conf.AppSecret}
		_, err := newIdentity(invalidConf, "email@example.com")
		Expect(err).Should(HaveOccurred())
	})
})
