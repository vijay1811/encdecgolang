package models

// Info ...
type Info struct {
	EncSymKey []byte
	Signature []byte
	Data      []byte
}

// Data ...
type Data struct {
	Name string
	Addr string
	Phone string
}