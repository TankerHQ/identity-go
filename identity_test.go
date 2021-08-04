package identity

import (
	"encoding/base64"
	"github.com/TankerHQ/identity-go/v3/internal/base64_json"
	"github.com/iancoleman/orderedmap"
	"golang.org/x/crypto/blake2b"

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
		provisionalIdentity, err := newProvisionalIdentity(conf, TargetEmail, "email@example.com")
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

		oldPublicProvisionalIdentity = "eyJ0cnVzdGNoYWluX2lkIjoidHBveHlOemgwaFU5RzJpOWFnTXZIeXlkK3BPNnpHQ2pPOUJmaHJDTGpkND0iLCJ0YXJnZXQiOiJlbWFpbCIsInZhbHVlIjoiYnJlbmRhbi5laWNoQHRhbmtlci5pbyIsInB1YmxpY19lbmNyeXB0aW9uX2tleSI6Ii8yajRkSTNyOFBsdkNOM3VXNEhoQTV3QnRNS09jQUNkMzhLNk4wcSttRlU9IiwicHVibGljX3NpZ25hdHVyZV9rZXkiOiJXN1FFUUJ1OUZYY1hJcE9ncTYydFB3Qml5RkFicFQxckFydUQwaC9OclRBPSJ9"
		newPublicProvisionalIdentity = "eyJ0cnVzdGNoYWluX2lkIjoidHBveHlOemgwaFU5RzJpOWFnTXZIeXlkK3BPNnpHQ2pPOUJmaHJDTGpkND0iLCJ0YXJnZXQiOiJoYXNoZWRfZW1haWwiLCJ2YWx1ZSI6IjB1MmM4dzhFSVpXVDJGelJOL3l5TTVxSWJFR1lUTkRUNVNrV1ZCdTIwUW89IiwicHVibGljX2VuY3J5cHRpb25fa2V5IjoiLzJqNGRJM3I4UGx2Q04zdVc0SGhBNXdCdE1LT2NBQ2QzOEs2TjBxK21GVT0iLCJwdWJsaWNfc2lnbmF0dXJlX2tleSI6Ilc3UUVRQnU5RlhjWElwT2dxNjJ0UHdCaXlGQWJwVDFyQXJ1RDBoL05yVEE9In0="
		phoneNumberProvisionalIdentity = "eyJ0cnVzdGNoYWluX2lkIjoidHBveHlOemgwaFU5RzJpOWFnTXZIeXlkK3BPNnpHQ2pPOUJmaHJDTGpkND0iLCJ0YXJnZXQiOiJwaG9uZV9udW1iZXIiLCJ2YWx1ZSI6IiszMzYxMTIyMzM0NCIsInB1YmxpY19lbmNyeXB0aW9uX2tleSI6Im42bTlYNUxmMFpuYXo4ZjArc2NoTElCTm0rcGlQaG5zWXZBdlh3MktFQXc9IiwicHJpdmF0ZV9lbmNyeXB0aW9uX2tleSI6InRWVFM5bkh4cjJNZFZ1VFI1Y2x3dzBFWGJ3aXM4SGl4Z1BJTmJRSngxVTQ9IiwicHVibGljX3NpZ25hdHVyZV9rZXkiOiJqcklEaWdTQ25BaTNHbDltSUFTbEFpU2hLQzdkQkxGVVpQOUN4TEdzYkg4PSIsInByaXZhdGVfc2lnbmF0dXJlX2tleSI6IlFIcWNMcjhicjZNM2JQblFtUWczcStxSENycDA1RGJjQnBMUGFUWlkwYTZPc2dPS0JJS2NDTGNhWDJZZ0JLVUNKS0VvTHQwRXNWUmsvMExFc2F4c2Z3PT0ifQ=="
		phoneNumberPublicProvisionalIdentity = "eyJ0cnVzdGNoYWluX2lkIjoidHBveHlOemgwaFU5RzJpOWFnTXZIeXlkK3BPNnpHQ2pPOUJmaHJDTGpkND0iLCJ0YXJnZXQiOiJoYXNoZWRfcGhvbmVfbnVtYmVyIiwidmFsdWUiOiJKZWFpUUFoOHg3amNpb1UybTRpaHkrQ3NISmx5Vys0VlZTU3M1U0hGVVR3PSIsInB1YmxpY19lbmNyeXB0aW9uX2tleSI6Im42bTlYNUxmMFpuYXo4ZjArc2NoTElCTm0rcGlQaG5zWXZBdlh3MktFQXc9IiwicHVibGljX3NpZ25hdHVyZV9rZXkiOiJqcklEaWdTQ25BaTNHbDltSUFTbEFpU2hLQzdkQkxGVVpQOUN4TEdzYkg4PSJ9"


		appID     = "tpoxyNzh0hU9G2i9agMvHyyd+pO6zGCjO9BfhrCLjd4="
		appSecret = "cTMoGGUKhwN47ypq4xAXAtVkNWeyUtMltQnYwJhxWYSvqjPVGmXd2wwa7y17QtPTZhn8bxb015CZC/e4ZI7+MQ=="
		userPhone = "+33611223344"

		appConfig = Config{
			AppID:     appID,
			AppSecret: appSecret,
		}
	)

	It("generates a valid identity in b64 form", func() {
		identityB64, err := Create(appConfig, "userID")
		Expect(err).ShouldNot(HaveOccurred())

		id := &identity{}
		err = base64_json.Decode(identityB64, id)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(id.Target).Should(Equal(TargetUser))
	})

	It("generates ordered JSON for permanent identities", func() {
		goodPermanentIdentity := "eyJ0cnVzdGNoYWluX2lkIjoidHBveHlOemgwaFU5RzJpOWFnTXZIeXlkK3BPNnpHQ2pPOUJmaHJDTGpkND0iLCJ0YXJnZXQiOiJ1c2VyIiwidmFsdWUiOiJSRGEwZXE0WE51ajV0VjdoZGFwak94aG1oZVRoNFFCRE5weTRTdnk5WG9rPSIsImRlbGVnYXRpb25fc2lnbmF0dXJlIjoiVTlXUW9sQ3ZSeWpUOG9SMlBRbWQxV1hOQ2kwcW1MMTJoTnJ0R2FiWVJFV2lyeTUya1d4MUFnWXprTHhINmdwbzNNaUE5cisremhubW9ZZEVKMCtKQ3c9PSIsImVwaGVtZXJhbF9wdWJsaWNfc2lnbmF0dXJlX2tleSI6IlhoM2kweERUcHIzSFh0QjJRNTE3UUt2M2F6TnpYTExYTWRKRFRTSDRiZDQ9IiwiZXBoZW1lcmFsX3ByaXZhdGVfc2lnbmF0dXJlX2tleSI6ImpFRFQ0d1FDYzFERndvZFhOUEhGQ2xuZFRQbkZ1Rm1YaEJ0K2lzS1U0WnBlSGVMVEVOT212Y2RlMEhaRG5YdEFxL2RyTTNOY3N0Y3gwa05OSWZodDNnPT0iLCJ1c2VyX3NlY3JldCI6IjdGU2YvbjBlNzZRVDNzMERrdmV0UlZWSmhYWkdFak94ajVFV0FGZXh2akk9In0="

		id := &identity{}
		err := base64_json.Decode(goodPermanentIdentity, id)
		Expect(err).ShouldNot(HaveOccurred())

		orderedJson, _ := base64_json.Encode(id)

		Expect(goodPermanentIdentity).Should(Equal(orderedJson))
	})

	It("can upgrade an identity", func() {
		identity, _ := Create(appConfig, "userID")
		publicIdentity, _ := GetPublicIdentity(identity)
		provIdentity, _ := CreateProvisional(appConfig, TargetEmail, "userID@tanker.io")
		publicProvIdentity, _ := GetPublicIdentity(provIdentity)

		identityJson, _ := base64.StdEncoding.DecodeString(identity)
		publicIdentityJson, _ := base64.StdEncoding.DecodeString(publicIdentity)
		provIdentityJson, _ := base64.StdEncoding.DecodeString(provIdentity)
		publicProvIdentityJson, _ := base64.StdEncoding.DecodeString(publicProvIdentity)

		upgradedIdentity, _ := UpgradeIdentity(identity)
		upgradedPublicIdentity, _ := UpgradeIdentity(publicIdentity)
		upgradedProvIdentity, _ := UpgradeIdentity(provIdentity)
		upgradedPublicProvIdentity, _ := UpgradeIdentity(publicProvIdentity)

		upgradedIdentityJson, _ := base64.StdEncoding.DecodeString(upgradedIdentity)
		upgradedPublicIdentityJson, _ := base64.StdEncoding.DecodeString(upgradedPublicIdentity)
		upgradedProvIdentityJson, _ := base64.StdEncoding.DecodeString(upgradedProvIdentity)
		upgradedPublicProvIdentityJson, _ := base64.StdEncoding.DecodeString(upgradedPublicProvIdentity)

		Expect(upgradedIdentityJson).Should(Equal(identityJson))
		Expect(upgradedPublicIdentityJson).Should(Equal(publicIdentityJson))
		Expect(upgradedProvIdentityJson).Should(Equal(provIdentityJson))
		Expect(upgradedPublicProvIdentityJson).Should(Equal(publicProvIdentityJson))
	})

	It("can upgrade an email provisional identity", func() {
		id := orderedmap.OrderedMap{}
		base64_json.Decode(newPublicProvisionalIdentity, &id)
		upgradedIdentity, err := UpgradeIdentity(oldPublicProvisionalIdentity)
		Expect(err).ShouldNot(HaveOccurred())

		Expect(upgradedIdentity).Should(Equal(newPublicProvisionalIdentity))
	})

	It("can fail to upgrade an identity to make codecov happy", func() {
		_, err := UpgradeIdentity("this is not going to deserialize very well")
		Expect(err).Should(HaveOccurred())
	})

	It("returns an error if the App secret is a valid base64 string but has an incorrect size", func() {
		invalidAppSecret := base64.StdEncoding.EncodeToString([]byte{0xaa})
		invalidConf := Config{AppID: appID, AppSecret: invalidAppSecret}
		_, err := Create(invalidConf, "email@example.com")
		Expect(err).Should(HaveOccurred())
	})

	It("returns an error if the App ID is a valid base64 string but has an incorrect size", func() {
		invalidAppID := base64.StdEncoding.EncodeToString([]byte{0xaa, 0xbb, 0xcc})
		invalidConf := Config{AppID: invalidAppID, AppSecret: appSecret}
		_, err := Create(invalidConf, "email@example.com")
		Expect(err).Should(HaveOccurred())
	})

	It("fails to generate a provisional identity with an invalid target", func() {
		_, err := CreateProvisional(appConfig, "INVALID!", "xxx")
		Expect(err).Should(HaveOccurred())
	})

	It("generates a valid provisional identity in b64 form", func() {
		identityB64, err := CreateProvisional(appConfig, TargetEmail, "email@example.com")
		Expect(err).ShouldNot(HaveOccurred())

		id := &provisionalIdentity{}
		err = base64_json.Decode(identityB64, id)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(id.Target).Should(Equal(TargetEmail))
		Expect(id.Value).Should(Equal("email@example.com"))
		Expect(id.PrivateEncryptionKey).ShouldNot(BeEmpty())
		Expect(id.PublicEncryptionKey).ShouldNot(BeEmpty())
		Expect(id.PrivateSignatureKey).ShouldNot(BeEmpty())
		Expect(id.PublicSignatureKey).ShouldNot(BeEmpty())
	})

	It("generates a valid phone_number provisional identity in b64 form", func() {
		identityB64, err := CreateProvisional(appConfig, TargetPhoneNumber, userPhone)
		Expect(err).ShouldNot(HaveOccurred())

		id := &provisionalIdentity{}
		err = base64_json.Decode(identityB64, id)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(id.Target).Should(Equal(TargetPhoneNumber))
		Expect(id.Value).Should(Equal(userPhone))
		Expect(id.PrivateEncryptionKey).ShouldNot(BeEmpty())
		Expect(id.PublicEncryptionKey).ShouldNot(BeEmpty())
		Expect(id.PrivateSignatureKey).ShouldNot(BeEmpty())
		Expect(id.PublicSignatureKey).ShouldNot(BeEmpty())
	})

	It("deserializes a valid phone_number provisional identity", func() {
		id := &provisionalIdentity{}
		err := base64_json.Decode(phoneNumberProvisionalIdentity, id)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(id.Target).Should(Equal(TargetPhoneNumber))
		Expect(id.Value).Should(Equal(userPhone))
		Expect(base64.StdEncoding.EncodeToString(id.PrivateEncryptionKey)).
			Should(Equal("tVTS9nHxr2MdVuTR5clww0EXbwis8HixgPINbQJx1U4="))
		Expect(base64.StdEncoding.EncodeToString(id.PublicEncryptionKey)).
			Should(Equal("n6m9X5Lf0Znaz8f0+schLIBNm+piPhnsYvAvXw2KEAw="))
		Expect(base64.StdEncoding.EncodeToString(id.PrivateSignatureKey)).
			Should(Equal("QHqcLr8br6M3bPnQmQg3q+qHCrp05DbcBpLPaTZY0a6OsgOKBIKcCLcaX2YgBKUCJKEoLt0EsVRk/0LEsaxsfw=="))
		Expect(base64.StdEncoding.EncodeToString(id.PublicSignatureKey)).
			Should(Equal("jrIDigSCnAi3Gl9mIASlAiShKC7dBLFUZP9CxLGsbH8="))
	})

	It("deserializes a valid phone_number public provisional identity", func() {
		privId := &provisionalIdentity{}
		err := base64_json.Decode(phoneNumberProvisionalIdentity, privId)
		Expect(err).ShouldNot(HaveOccurred())
		hashedPhone := hashProvisionalIdentityValue(userPhone, base64.StdEncoding.EncodeToString(privId.PrivateSignatureKey))

		publicIdentity, _ := GetPublicIdentity(phoneNumberProvisionalIdentity)
		Expect(publicIdentity).Should(Equal(phoneNumberPublicProvisionalIdentity))

		id := &publicProvisionalIdentity{}
		err2 := base64_json.Decode(publicIdentity, id)
		Expect(err2).ShouldNot(HaveOccurred())
		Expect(id.Target).Should(Equal(TargetHashedPhoneNumber))
		Expect(id.Value).Should(Equal(hashedPhone))
		Expect(base64.StdEncoding.EncodeToString(id.PublicEncryptionKey)).
			Should(Equal("n6m9X5Lf0Znaz8f0+schLIBNm+piPhnsYvAvXw2KEAw="))
		Expect(base64.StdEncoding.EncodeToString(id.PublicSignatureKey)).
			Should(Equal("jrIDigSCnAi3Gl9mIASlAiShKC7dBLFUZP9CxLGsbH8="))
	})

	It("creates a valid public identity from an identity", func() {
		publicID, err := GetPublicIdentity(goodIdentity)
		Expect(err).ShouldNot(HaveOccurred())

		extractedPublicID := &publicIdentity{}
		_ = base64_json.Decode(publicID, extractedPublicID)

		extractedGoodPublicID := &publicIdentity{}
		_ = base64_json.Decode(goodPublicIdentity, extractedGoodPublicID)
		Expect(*extractedGoodPublicID).Should(Equal(*extractedPublicID))
	})

	It("creates a valid public identity from a provisional identity", func() {
		email := "email@example.com"
		hashedEmail := blake2b.Sum256([]byte(email))
		identityB64, err := CreateProvisional(appConfig, TargetEmail, email)
		Expect(err).ShouldNot(HaveOccurred())

		provisionalID := &provisionalIdentity{}
		err = base64_json.Decode(identityB64, provisionalID)
		Expect(err).ShouldNot(HaveOccurred())

		publicID, err := GetPublicIdentity(identityB64)
		Expect(err).ShouldNot(HaveOccurred())

		expectedId := provisionalID.publicProvisionalIdentity
		expectedId.Target = TargetHashedEmail
		expectedId.Value = base64.StdEncoding.EncodeToString(hashedEmail[:])

		extractedPublicID := &publicProvisionalIdentity{}
		err = base64_json.Decode(publicID, extractedPublicID)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(*extractedPublicID).Should(Equal(expectedId))
	})
})