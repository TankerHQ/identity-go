package identity

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"github.com/TankerHQ/identity-go/v3/internal/base64_json"
	"io"
	"testing"
)

func byteArray(n int) []byte {
	buf := make([]byte, n)
	rand.Read(buf)
	return buf
}

func base64id(n int) string {
	return base64.StdEncoding.EncodeToString(byteArray(n))
}

var (
	goodAppSecretRaw   = byteArray(AppSecretSize)
	validAppSecret     = base64.StdEncoding.EncodeToString(goodAppSecretRaw)
	wrongSizeAppSecret = base64.StdEncoding.EncodeToString(goodAppSecretRaw[2:])

	validAppId     = base64.StdEncoding.EncodeToString(getAppId(goodAppSecretRaw))
	wrongSizeAppId = base64id(AppPublicKeySize / 2)

	notBase64Identity = "some identity"

	validConf = Config{
		AppID:     validAppId,
		AppSecret: validAppSecret,
	}

	badConfsVector = []struct {
		desc   string
		config Config
	}{
		{
			desc: "WrongSizeAppId",
			config: Config{
				AppID:     wrongSizeAppId,
				AppSecret: validAppSecret,
			},
		},
		{
			desc: "WrongSizeAppSecret",
			config: Config{
				AppID:     validAppId,
				AppSecret: wrongSizeAppSecret,
			},
		},
		{
			desc: "NotBase64AppId",
			config: Config{
				AppID:     "app ID",
				AppSecret: validAppSecret,
			},
		},
		{
			desc: "NotBase64AppSecret",
			config: Config{
				AppID:     validAppId,
				AppSecret: "app secret",
			},
		},
		{
			desc: "AppIdSecretMismatch",
			config: Config{
				AppID:     base64id(AppPublicKeySize),
				AppSecret: validAppSecret,
			},
		},
	}

	validTargets = []string{
		"email",
		"phone_number",
	}

	invalidTarget = "____not_a_good_target____"
)

func TestCreate(t *testing.T) {
	conf := Config{
		AppID:     validAppId,
		AppSecret: validAppSecret,
	}

	id, err := Create(conf, "userID")
	if err != nil || id == nil || *id == "" {
		t.Fatal("error creating identity with valid config")
	}
}

func TestCreate_Error(t *testing.T) {

	for _, conf := range badConfsVector {
		t.Run(conf.desc, func(t *testing.T) {
			_, err := Create(conf.config, "userID")
			if err == nil {
				t.Fatal("no error creating identity")
			}
		})
	}

	t.Run("UnavailableRandReader", func(t *testing.T) {
		r := rand.Reader
		defer func() {
			rand.Reader = r
		}()

		rand.Reader = bytes.NewBuffer(nil)
		_, err := Create(validConf, "userID")
		if err == nil {
			t.Fatal("no error creating identity")
		}
	})
}

func TestCreateProvisional(t *testing.T) {
	for _, validTarget := range validTargets {
		t.Run("Target/"+validTarget, func(t *testing.T) {
			id, err := CreateProvisional(validConf, validTarget, "userID")
			if err != nil || id == nil || *id == "" {
				t.Fatal("error creating provisional identity with valid config")
			}
		})
	}
}

// singleSuccessReader is a helper type to test the case when the first
// rand.Read succeeds but not the second
type singleSuccessReader struct {
	r io.Reader
	n int
}

func (s *singleSuccessReader) Read(p []byte) (int, error) {
	if s.n == 1 {
		return 0, errors.New("no more to read")
	}
	s.n++
	return s.r.Read(p)
}

func TestCreateProvisional_Error(t *testing.T) {
	for _, conf := range badConfsVector {
		for _, target := range validTargets {
			t.Run(conf.desc+"/"+target, func(t *testing.T) {
				_, err := CreateProvisional(conf.config, target, "userID")
				if err == nil {
					t.Fatal("no error creating provisional identity")
				}
			})
		}
	}

	t.Run("InvalidTarget", func(t *testing.T) {
		_, err := CreateProvisional(validConf, invalidTarget, "userID")
		if err == nil {
			t.Fatal("no error creating provisional identity")
		}
	})

	t.Run("UnavailableRandReader", func(t *testing.T) {
		r := rand.Reader
		defer func() {
			rand.Reader = r
		}()

		rand.Reader = bytes.NewBuffer(nil)
		_, err := CreateProvisional(validConf, validTargets[0], "userID")
		if err == nil {
			t.Fatal("no error creating provisional identity")
		}
	})

	t.Run("DisruptedRandReader", func(t *testing.T) {
		r := rand.Reader
		defer func() {
			rand.Reader = r
		}()

		rand.Reader = &singleSuccessReader{r: r, n: 0}
		_, err := CreateProvisional(validConf, validTargets[0], "userID")
		if err == nil {
			t.Fatal("no error creating provisional identity")
		}
	})
}

func assertStablePublic(t *testing.T, id *string) {
	pub, err := GetPublicIdentity(*id)
	if err != nil {
		t.Fatal("error getting public identity")
	}

	pub2, err := GetPublicIdentity(*id)
	if err != nil {
		t.Fatal("error getting public identity")
	}

	if *pub != *pub2 {
		t.Fatal("public identities differ")
	}
}

func TestGetPublicIdentity_Identity(t *testing.T) {
	id, err := Create(validConf, "userId")
	if err != nil {
		panic("err should be nil")
	}

	assertStablePublic(t, id)
}

func TestGetPublicIdentity_ProvisionalIdentity(t *testing.T) {
	for _, target := range validTargets {
		provisional, err := CreateProvisional(validConf, target, "userId")
		if err != nil {
			panic("error creating provisional identity")
		}

		t.Run(target, func(t *testing.T) {
			assertStablePublic(t, provisional)
		})
	}
}

func TestGetPublicIdentity_Error(t *testing.T) {
	t.Run("BadTarget", func(t *testing.T) {
		fakeIdentity := map[string]string{
			"target": invalidTarget,
		}

		fakeIdentityEncoded, err := base64_json.Encode(fakeIdentity)
		if err != nil {
			panic("error encoding fakeIdentity")
		}

		_, err = GetPublicIdentity(*fakeIdentityEncoded)
		if err == nil {
			t.Fatal("no error getting public identity")
		}
	})

	t.Run("InvalidIdentity", func(t *testing.T) {
		fakeIdentity := map[string]string{
			"target": "phone_number",
		}

		fakeIdentityEncoded, err := base64_json.Encode(fakeIdentity)
		if err != nil {
			panic("error encoding identity")
		}

		_, err = GetPublicIdentity(*fakeIdentityEncoded)
		if err == nil {
			t.Fatal("no error getting public identity")
		}
	})

	t.Run("InvalidBase64", func(t *testing.T) {
		_, err := GetPublicIdentity(notBase64Identity)
		if err == nil {
			t.Fatal("no error getting public identity")
		}
	})
}

func TestUpgradeIdentity(t *testing.T) {
	for _, target := range validTargets {
		prov, err := CreateProvisional(validConf, target, "userId")
		if err != nil {
			panic("error creating provisional identity")
		}
		pubProv, err := GetPublicIdentity(*prov)
		if err != nil {
			panic("error getting public identity")
		}

		t.Run("Private/"+target, func(t *testing.T) {
			_, err := UpgradeIdentity(*prov)
			if err != nil {
				t.Fatal("error upgrading identity")
			}
		})
		t.Run("Public/"+target, func(t *testing.T) {
			_, err := UpgradeIdentity(*pubProv)
			if err != nil {
				t.Fatal("error upgrading identity")
			}
		})
	}

	t.Run("EmailNotPrivate", func(t *testing.T) {
		fakeIdentity := map[string]string{
			"target": "email",
			"value":  "value",
		}

		fakeIdentityEncoded, _ := base64_json.Encode(fakeIdentity)
		_, err := UpgradeIdentity(*fakeIdentityEncoded)
		if err != nil {
			t.Fatal("error upgrading identity")
		}
	})
}

func TestUpgradeIdentity_Error(t *testing.T) {
	t.Run("BadBase64", func(t *testing.T) {
		_, err := UpgradeIdentity(notBase64Identity)
		if err == nil {
			t.Fatal("no error upgrading identity")
		}
	})

	t.Run("NoTarget", func(t *testing.T) {
		noTarget := map[string]string{}
		noTargetEncoded, _ := base64_json.Encode(noTarget)
		_, err := UpgradeIdentity(*noTargetEncoded)
		if err == nil {
			t.Fatal("no error upgrading identity")
		}
	})

	t.Run("EmailNotPrivateNoValue", func(t *testing.T) {
		fakeIdentity := map[string]string{
			"target": "email",
		}

		fakeIdentityEncoded, _ := base64_json.Encode(fakeIdentity)
		_, err := UpgradeIdentity(*fakeIdentityEncoded)
		if err == nil {
			t.Fatal("no error upgrading identity")
		}
	})
}
