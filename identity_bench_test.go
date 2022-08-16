package identity_test

import (
	"testing"

	"github.com/TankerHQ/identity-go/v3"
)

func BenchmarkCreate(b *testing.B) {
	for i := 0; i < b.N; i++ {
		identity.Create(validConf, "userID") //nolint: errcheck
	}
}

func BenchmarkCreateProvisional(b *testing.B) {
	for _, target := range validTargets {
		b.Run(target, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				identity.CreateProvisional(validConf, target, "userID") //nolint: errcheck
			}
		})
	}
}

func BenchmarkGetPublicIdentity(b *testing.B) {
	for _, target := range validTargets {
		provIdentity, _ := identity.CreateProvisional(validConf, target, "userID") //nolint: errcheck
		b.Run(target, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				identity.GetPublicIdentity(*provIdentity) //nolint: errcheck
			}
		})
	}
}

func BenchmarkUpgradeIdentity(b *testing.B) {
	ident, _ := identity.Create(validConf, "userID")
	for i := 0; i < b.N; i++ {
		identity.UpgradeIdentity(*ident) //nolint: errcheck
	}
}
