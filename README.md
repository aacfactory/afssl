# AFSSL
SSL Generator. 

## Install
```shell
go get github.com/aacfactory/afssl
```

## Usage
```go
config := afssl.CertificateConfig{
    Country:            "CN",
    Province:           "Shanghai",
    City:               "Shanghai",
    Organization:       "AACFACTORY",
    OrganizationalUnit: "TECH",
    CommonName:         "AFSSL",
    IPs:                nil,
    Emails:             nil,
    DNSNames:           nil,
}
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

