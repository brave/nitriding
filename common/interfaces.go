package common

type Builder[T any] interface {
	Build() (T, error)
}
