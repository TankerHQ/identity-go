package identity

type Target = string

const (
	TargetEmail             Target = "email"
	TargetHashedEmail       Target = "hashed_email"
	TargetUser              Target = "user"
	TargetPhoneNumber       Target = "phone_number"
	TargetHashedPhoneNumber Target = "hashed_phone_number"
)

func ToHashed(target Target) Target {
	switch target {
	case TargetEmail:
		return TargetHashedEmail
	case TargetPhoneNumber:
		return TargetHashedPhoneNumber
	default:
		return target
	}
}
