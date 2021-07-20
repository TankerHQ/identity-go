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
		Expect(identity.Target).To(Equal(TargetUser))
		Expect(identity.Value).To(Equal(base64.StdEncoding.EncodeToString(obfuscatedUserID)))
		checkDelegationSignature(identity, trustchainPublicKey)
	})

	It("newProvisionalIdentity returns a valid tanker provisional identity", func() {
		provisionalIdentity, err := newProvisionalIdentity(conf, "email@example.com")
		Expect(err).ShouldNot(HaveOccurred())

		Expect(provisionalIdentity.TrustchainID).To(Equal(AppID))
		Expect(provisionalIdentity.Target).To(Equal(TargetEmail))
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

var _ = Describe("generate", func() {
	var (
		goodIdentity = "eyJ0cnVzdGNoYWluX2lkIjoidHBveHlOemgwaFU5RzJpOWFnTXZIeXlkK3BPNnpHQ2pPOUJmaHJDTGpkND0iLCJ0YXJnZXQiOiJ1c2VyIiwidmFsdWUiOiJSRGEwZXE0WE51ajV0VjdoZGFwak94aG1oZVRoNFFCRE5weTRTdnk5WG9rPSIsImRlbGVnYXRpb25fc2lnbmF0dXJlIjoiVTlXUW9sQ3ZSeWpUOG9SMlBRbWQxV1hOQ2kwcW1MMTJoTnJ0R2FiWVJFV2lyeTUya1d4MUFnWXprTHhINmdwbzNNaUE5cisremhubW9ZZEVKMCtKQ3c9PSIsImVwaGVtZXJhbF9wdWJsaWNfc2lnbmF0dXJlX2tleSI6IlhoM2kweERUcHIzSFh0QjJRNTE3UUt2M2F6TnpYTExYTWRKRFRTSDRiZDQ9IiwiZXBoZW1lcmFsX3ByaXZhdGVfc2lnbmF0dXJlX2tleSI6ImpFRFQ0d1FDYzFERndvZFhOUEhGQ2xuZFRQbkZ1Rm1YaEJ0K2lzS1U0WnBlSGVMVEVOT212Y2RlMEhaRG5YdEFxL2RyTTNOY3N0Y3gwa05OSWZodDNnPT0iLCJ1c2VyX3NlY3JldCI6IjdGU2YvbjBlNzZRVDNzMERrdmV0UlZWSmhYWkdFak94ajVFV0FGZXh2akk9In0="

		goodPublicIdentity = "eyJ0YXJnZXQiOiJ1c2VyIiwidHJ1c3RjaGFpbl9pZCI6InRwb3h5TnpoMGhVOUcyaTlhZ012SHl5ZCtwTzZ6R0NqTzlCZmhyQ0xqZDQ9IiwidmFsdWUiOiJSRGEwZXE0WE51ajV0VjdoZGFwak94aG1oZVRoNFFCRE5weTRTdnk5WG9rPSJ9"

		appID     = "tpoxyNzh0hU9G2i9agMvHyyd+pO6zGCjO9BfhrCLjd4="
		appSecret = "cTMoGGUKhwN47ypq4xAXAtVkNWeyUtMltQnYwJhxWYSvqjPVGmXd2wwa7y17QtPTZhn8bxb015CZC/e4ZI7+MQ=="

		appConfig = Config{
			AppID:     appID,
			AppSecret: appSecret,
		}
	)

	It("generates a valid identity in b64 form", func() {
		identityB64, err := New(appConfig, "userID")
		Expect(err).ShouldNot(HaveOccurred())

		id := &identity{}
		err = Base64JsonDecode(identityB64, id)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(id.Target).Should(Equal(TargetUser))
	})

	It("returns an error if the App secret is a valid base64 string but has an incorrect size", func() {
		invalidAppSecret := base64.StdEncoding.EncodeToString([]byte{0xaa})
		invalidConf := Config{AppID: appID, AppSecret: invalidAppSecret}
		_, err := New(invalidConf, "email@example.com")
		Expect(err).Should(HaveOccurred())
	})

	It("returns an error if the App ID is a valid base64 string but has an incorrect size", func() {
		invalidAppID := base64.StdEncoding.EncodeToString([]byte{0xaa, 0xbb, 0xcc})
		invalidConf := Config{AppID: invalidAppID, AppSecret: appSecret}
		_, err := New(invalidConf, "email@example.com")
		Expect(err).Should(HaveOccurred())
	})

	It("generates a valid provisional identity in b64 form", func() {
		identityB64, err := NewProvisional(appConfig, "email@example.com")
		Expect(err).ShouldNot(HaveOccurred())

		id := &provisionalIdentity{}
		err = Base64JsonDecode(identityB64, id)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(id.Target).Should(Equal(TargetEmail))
		Expect(id.Value).Should(Equal("email@example.com"))
		Expect(id.PrivateEncryptionKey).ShouldNot(BeEmpty())
		Expect(id.PublicEncryptionKey).ShouldNot(BeEmpty())
		Expect(id.PrivateSignatureKey).ShouldNot(BeEmpty())
		Expect(id.PublicSignatureKey).ShouldNot(BeEmpty())
	})

	It("creates a valid public identity from an identity", func() {
		publicID, err := GetPublic(goodIdentity)
		Expect(err).ShouldNot(HaveOccurred())

		extractedPublicID := &publicIdentity{}
		_ = Base64JsonDecode(publicID, extractedPublicID)

		extractedGoodPublicID := &publicIdentity{}
		_ = Base64JsonDecode(goodPublicIdentity, extractedGoodPublicID)
		Expect(*extractedGoodPublicID).Should(Equal(*extractedPublicID))
	})

	It("creates a valid public identity from a provisional identity", func() {
		identityB64, err := NewProvisional(appConfig, "email@example.com")
		Expect(err).ShouldNot(HaveOccurred())

		provisionalID := &provisionalIdentity{}
		_ = Base64JsonDecode(identityB64, provisionalID)
		Expect(err).ShouldNot(HaveOccurred())

		publicID, err := GetPublic(identityB64)
		Expect(err).ShouldNot(HaveOccurred())

		extractedPublicID := &publicProvisionalIdentity{}
		_ = Base64JsonDecode(publicID, extractedPublicID)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(*extractedPublicID).Should(Equal(provisionalID.publicProvisionalIdentity))
	})
})
