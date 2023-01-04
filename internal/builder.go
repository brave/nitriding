package internal

type Builder[T any] interface {
	Build() (T, error)
}
