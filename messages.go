package nitriding

type Nonce struct {
	Value []byte `validate:"required,lte=20"`
}

type TLSCertFpr struct {
	Value []byte `validate:"required,eq=32"`
}

type ServerInfo struct {
	InEnclave bool   `validate:"required"`
	CodeURL   string `validate:"required"`
}
