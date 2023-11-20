# AFSSL
SSL Generator. 

## Install
```shell
go get github.com/aacfactory/afssl
```

## Usage
Generate Self Signed SSL.
```go
config := afssl.CertificateConfig{}
// ca
caPEM, caKeyPEM, caErr := afssl.GenerateCertificate(config, afssl.CA())
if caErr != nil {
    t.Error("ca", caErr)
    return
}
fmt.Println(string(caPEM))
fmt.Println(string(caKeyPEM))
// server
serverPEM, serverKeyPEM, serverErr := afssl.GenerateCertificate(config, afssl.WithParent(caPEM, caKeyPEM))
if serverErr != nil {
    t.Error("server", serverErr)
    return
}
fmt.Println(string(serverPEM))
fmt.Println(string(serverKeyPEM))
// client
clientPEM, clientKeyPEM, clientErr := afssl.GenerateCertificate(config, afssl.WithParent(caPEM, caKeyPEM))
if clientErr != nil {
    t.Error("client", clientErr)
    return
}
fmt.Println(string(clientPEM))
fmt.Println(string(clientKeyPEM))
```

## Use as bin
```shell
go install github.com/aacfactory/afssl/commands/afssl@latest
```

```shell
afssl --type={RSA,ECDSA,ED25519,SM2} --ca --expire={days} --cn={CN} {dst path}
```
