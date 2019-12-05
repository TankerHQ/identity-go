package identity

import (
	"github.com/TankerHQ/identity-go/b64json"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("generate", func() {
	var (
		goodIdentity = "eyJ0cnVzdGNoYWluX2lkIjoidHBveHlOemgwaFU5RzJpOWFnTXZIeXlkK3BPNnpHQ2pPOUJmaHJDTGpkND0iLCJ0YXJnZXQiOiJ1c2VyIiwidmFsdWUiOiJSRGEwZXE0WE51ajV0VjdoZGFwak94aG1oZVRoNFFCRE5weTRTdnk5WG9rPSIsImRlbGVnYXRpb25fc2lnbmF0dXJlIjoiVTlXUW9sQ3ZSeWpUOG9SMlBRbWQxV1hOQ2kwcW1MMTJoTnJ0R2FiWVJFV2lyeTUya1d4MUFnWXprTHhINmdwbzNNaUE5cisremhubW9ZZEVKMCtKQ3c9PSIsImVwaGVtZXJhbF9wdWJsaWNfc2lnbmF0dXJlX2tleSI6IlhoM2kweERUcHIzSFh0QjJRNTE3UUt2M2F6TnpYTExYTWRKRFRTSDRiZDQ9IiwiZXBoZW1lcmFsX3ByaXZhdGVfc2lnbmF0dXJlX2tleSI6ImpFRFQ0d1FDYzFERndvZFhOUEhGQ2xuZFRQbkZ1Rm1YaEJ0K2lzS1U0WnBlSGVMVEVOT212Y2RlMEhaRG5YdEFxL2RyTTNOY3N0Y3gwa05OSWZodDNnPT0iLCJ1c2VyX3NlY3JldCI6IjdGU2YvbjBlNzZRVDNzMERrdmV0UlZWSmhYWkdFak94ajVFV0FGZXh2akk9In0="

		goodPublicIdentity = "eyJ0YXJnZXQiOiJ1c2VyIiwidHJ1c3RjaGFpbl9pZCI6InRwb3h5TnpoMGhVOUcyaTlhZ012SHl5ZCtwTzZ6R0NqTzlCZmhyQ0xqZDQ9IiwidmFsdWUiOiJSRGEwZXE0WE51ajV0VjdoZGFwak94aG1oZVRoNFFCRE5weTRTdnk5WG9rPSJ9"

		userToken = "eyJkZWxlZ2F0aW9uX3NpZ25hdHVyZSI6IlU5V1FvbEN2UnlqVDhvUjJQUW1kMVdYTkNpMHFtTDEyaE5ydEdhYllSRVdpcnk1MmtXeDFBZ1l6a0x4SDZncG8zTWlBOXIrK3pobm1vWWRFSjArSkN3PT0iLCJlcGhlbWVyYWxfcHJpdmF0ZV9zaWduYXR1cmVfa2V5IjoiakVEVDR3UUNjMURGd29kWE5QSEZDbG5kVFBuRnVGbVhoQnQraXNLVTRacGVIZUxURU5PbXZjZGUwSFpEblh0QXEvZHJNM05jc3RjeDBrTk5JZmh0M2c9PSIsImVwaGVtZXJhbF9wdWJsaWNfc2lnbmF0dXJlX2tleSI6IlhoM2kweERUcHIzSFh0QjJRNTE3UUt2M2F6TnpYTExYTWRKRFRTSDRiZDQ9IiwidXNlcl9pZCI6IlJEYTBlcTRYTnVqNXRWN2hkYXBqT3hobWhlVGg0UUJETnB5NFN2eTlYb2s9IiwidXNlcl9zZWNyZXQiOiI3RlNmL24wZTc2UVQzczBEa3ZldFJWVkpoWFpHRWpPeGo1RVdBRmV4dmpJPSJ9"
		userID    = "b_eich"

		appConfig = Config{
			AppID:     "tpoxyNzh0hU9G2i9agMvHyyd+pO6zGCjO9BfhrCLjd4=",
			AppSecret: "cTMoGGUKhwN47ypq4xAXAtVkNWeyUtMltQnYwJhxWYSvqjPVGmXd2wwa7y17QtPTZhn8bxb015CZC/e4ZI7+MQ==",
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

	It("upgrades a user token to an identity", func() {
		upgradedIdentity, err := UpgradeUserToken(appConfig, userID, userToken)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(upgradedIdentity).Should(Equal(&goodIdentity))
	})
})
