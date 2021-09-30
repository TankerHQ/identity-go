package identity_test

import (
	"github.com/TankerHQ/identity-go/v3"
	"testing"
)

func BenchmarkCreate(b *testing.B) {
	for i := 0 ; i < b.N ; i++ {
		identity.Create(validConf, "userID")
	}
}

func BenchmarkCreateProvisional(b *testing.B) {
	for _, target := range validTargets {
		b.Run(string(target), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				identity.CreateProvisional(validConf, target, "userID")
			}
		})
	}
}

func BenchmarkGetPublicIdentity(b *testing.B) {
	for _, target := range validTargets {
		provIdentity, _ := identity.CreateProvisional(validConf, target, "userID")
		b.Run(string(target), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				identity.GetPublicIdentity(*provIdentity)
			}
		})
	}
}

func BenchmarkUpgradeIdentity(b *testing.B) {
	ident, _ := identity.Create(validConf, "userID")
	for i := 0 ; i < b.N ; i++ {
		identity.UpgradeIdentity(*ident)
	}
}