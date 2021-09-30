package identity

// Target is the target for an Identity. It can take values among
// "email", "phone_number" and "user"
type Target string

const (
	Email Target = "email"
	PhoneNumber Target = "phone_number"
	User Target = "user"
)

// Hashed returns the hashed equivalent of t
func (t Target) Hashed() Target {
	return "hashed_" + t
}