package identity

import (
	"encoding/base64"

	"github.com/TankerHQ/identity-go/v2/b64json"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

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
		identityB64, err := Create(appConfig, "userID")
		Expect(err).ShouldNot(HaveOccurred())

		id := &identity{}
		err = b64json.Decode(*identityB64, id)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(id.Target).Should(Equal("user"))
	})

	It("generates ordered JSON for permanent identities", func() {
		goodPermanentIdentity := "eyJ0cnVzdGNoYWluX2lkIjoidHBveHlOemgwaFU5RzJpOWFnTXZIeXlkK3BPNnpHQ2pPOUJmaHJDTGpkND0iLCJ0YXJnZXQiOiJ1c2VyIiwidmFsdWUiOiJSRGEwZXE0WE51ajV0VjdoZGFwak94aG1oZVRoNFFCRE5weTRTdnk5WG9rPSIsImRlbGVnYXRpb25fc2lnbmF0dXJlIjoiVTlXUW9sQ3ZSeWpUOG9SMlBRbWQxV1hOQ2kwcW1MMTJoTnJ0R2FiWVJFV2lyeTUya1d4MUFnWXprTHhINmdwbzNNaUE5cisremhubW9ZZEVKMCtKQ3c9PSIsImVwaGVtZXJhbF9wdWJsaWNfc2lnbmF0dXJlX2tleSI6IlhoM2kweERUcHIzSFh0QjJRNTE3UUt2M2F6TnpYTExYTWRKRFRTSDRiZDQ9IiwiZXBoZW1lcmFsX3ByaXZhdGVfc2lnbmF0dXJlX2tleSI6ImpFRFQ0d1FDYzFERndvZFhOUEhGQ2xuZFRQbkZ1Rm1YaEJ0K2lzS1U0WnBlSGVMVEVOT212Y2RlMEhaRG5YdEFxL2RyTTNOY3N0Y3gwa05OSWZodDNnPT0iLCJ1c2VyX3NlY3JldCI6IjdGU2YvbjBlNzZRVDNzMERrdmV0UlZWSmhYWkdFak94ajVFV0FGZXh2akk9In0="

		id := &identity{}
		err := b64json.Decode(goodPermanentIdentity, id)
		Expect(err).ShouldNot(HaveOccurred())

		orderedJson, _ := b64json.Encode(id)

		Expect(goodPermanentIdentity).Should(Equal(*orderedJson))
	})

	It("can upgrade an identity", func() {
		identity, _ := Create(appConfig, "userID")
		publicIdentity, _ := GetPublicIdentity(*identity)
		provIdentity, _ := CreateProvisional(appConfig, "userID@tanker.io")
		publicProvIdentity, _ := GetPublicIdentity(*provIdentity)

		identityJson, _ := base64.StdEncoding.DecodeString(*identity)
		publicIdentityJson, _ := base64.StdEncoding.DecodeString(*publicIdentity)
		provIdentityJson, _ := base64.StdEncoding.DecodeString(*provIdentity)
		publicProvIdentityJson, _ := base64.StdEncoding.DecodeString(*publicProvIdentity)

		upgradedIdentity, _ := UpgradeIdentity(*identity)
		upgradedPublicIdentity, _ := UpgradeIdentity(*publicIdentity)
		upgradedProvIdentity, _ := UpgradeIdentity(*provIdentity)
		upgradedPublicProvIdentity, _ := UpgradeIdentity(*publicProvIdentity)

		upgradedIdentityJson, _ := base64.StdEncoding.DecodeString(*upgradedIdentity)
		upgradedPublicIdentityJson, _ := base64.StdEncoding.DecodeString(*upgradedPublicIdentity)
		upgradedProvIdentityJson, _ := base64.StdEncoding.DecodeString(*upgradedProvIdentity)
		upgradedPublicProvIdentityJson, _ := base64.StdEncoding.DecodeString(*upgradedPublicProvIdentity)

		Expect(upgradedIdentityJson).Should(Equal(identityJson))
		Expect(upgradedPublicIdentityJson).Should(Equal(publicIdentityJson))
		Expect(upgradedProvIdentityJson).Should(Equal(provIdentityJson))
		Expect(upgradedPublicProvIdentityJson).Should(Equal(publicProvIdentityJson))
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

	It("generates a valid provisional identity in b64 form", func() {
		identityB64, err := CreateProvisional(appConfig, "email@example.com")
		Expect(err).ShouldNot(HaveOccurred())

		id := &provisionalIdentity{}
		err = b64json.Decode(*identityB64, id)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(id.Target).Should(Equal("email"))
		Expect(id.Value).Should(Equal("email@example.com"))
		Expect(id.PrivateEncryptionKey).ShouldNot(BeEmpty())
		Expect(id.PublicEncryptionKey).ShouldNot(BeEmpty())
		Expect(id.PrivateSignatureKey).ShouldNot(BeEmpty())
		Expect(id.PublicSignatureKey).ShouldNot(BeEmpty())
	})

	It("creates a valid public identity from an identity", func() {
		publicID, err := GetPublicIdentity(goodIdentity)
		Expect(err).ShouldNot(HaveOccurred())

		extractedPublicID := &publicIdentity{}
		_ = b64json.Decode(*publicID, extractedPublicID)

		extractedGoodPublicID := &publicIdentity{}
		_ = b64json.Decode(goodPublicIdentity, extractedGoodPublicID)
		Expect(*extractedGoodPublicID).Should(Equal(*extractedPublicID))
	})

	It("creates a valid public identity from a provisional identity", func() {
		identityB64, err := CreateProvisional(appConfig, "email@example.com")
		Expect(err).ShouldNot(HaveOccurred())

		provisionalID := &provisionalIdentity{}
		_ = b64json.Decode(*identityB64, provisionalID)
		Expect(err).ShouldNot(HaveOccurred())

		publicID, err := GetPublicIdentity(*identityB64)
		Expect(err).ShouldNot(HaveOccurred())

		extractedPublicID := &publicProvisionalIdentity{}
		_ = b64json.Decode(*publicID, extractedPublicID)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(*extractedPublicID).Should(Equal(provisionalID.publicProvisionalIdentity))
	})
})
