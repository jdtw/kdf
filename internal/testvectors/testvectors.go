package testvectors

//go:generate go run github.com/jdtw/kdf/internal/testvectors/parse --in NIST_HMAC_vectors.txt --out generated.go
//go:generate go fmt generated.go
