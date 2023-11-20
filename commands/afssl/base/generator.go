package base

import (
	"fmt"
	"github.com/aacfactory/afssl"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func Generate(args []string) (err error) {
	keyType := afssl.ECDSA()
	ca := false
	cn := "AFSSL"
	expire := 356
	dst := "."
	if argsLen := len(args); argsLen > 0 {
		for i, arg := range args {
			arg = strings.TrimSpace(arg)
			if arg == "" {
				continue
			}
			if strings.Index(arg, "--type=") == 0 {
				kt := strings.ToUpper(arg[7:])
				switch kt {
				case "RSA":
					keyType = afssl.RSA()
					break
				case "ECDSA":
					keyType = afssl.ECDSA()
					break
				case "ED25519":
					keyType = afssl.ED25519()
					break
				case "SM2":
					keyType = afssl.SM2()
					break
				default:
					err = fmt.Errorf("afssl: generate failed, invalid key type")
					return
				}
				continue
			}
			if strings.Index(arg, "--cn=") == 0 {
				cn = arg[5:]
				continue
			}
			if strings.Index(arg, "--ca") == 0 {
				ca = true
				continue
			}
			if strings.Index(arg, "--expire=") == 0 {
				exp := strings.TrimSpace(arg[9:])
				expire, err = strconv.Atoi(exp)
				if err != nil || expire < 1 {
					err = fmt.Errorf("afssl: generate failed, invalid expire")
					return
				}
				continue
			}
			if i == argsLen-1 {
				dst = arg
			}
		}
	}
	outputDir, dirErr := filepath.Abs(dst)
	if dirErr != nil {
		err = fmt.Errorf("afssl: generate failed, invalid dst path")
		return
	}
	stat, statErr := os.Stat(outputDir)
	if statErr != nil {
		if os.IsNotExist(statErr) {
			mdErr := os.MkdirAll(outputDir, 0644)
			if mdErr != nil {
				err = fmt.Errorf("afssl: generate failed, invalid dst path")
				return
			}
		}
	} else {
		if !stat.IsDir() {
			err = fmt.Errorf("afssl: generate failed, invalid dst path")
			return
		}
	}

	config := afssl.CertificateConfig{
		Subject: &afssl.CertificatePkixName{
			CommonName: cn,
		},
		IPs:      nil,
		Emails:   nil,
		DNSNames: nil,
	}
	options := make([]afssl.GenerateCertificateOption, 0, 1)
	options = append(options, afssl.WithKeyType(keyType))
	if ca {
		options = append(options, afssl.CA())
	}
	options = append(options, afssl.WithExpirationDays(expire))

	cert, key, genErr := afssl.GenerateCertificate(config, options...)
	if genErr != nil {
		err = fmt.Errorf("afssl: generate failed, %v", genErr)
		return
	}
	err = os.WriteFile(filepath.Join(outputDir, "ca.crt"), cert, 0644)
	if err != nil {
		err = fmt.Errorf("afssl: generate failed, %v", err)
		return
	}
	err = os.WriteFile(filepath.Join(outputDir, "ca.key"), key, 0644)
	if err != nil {
		err = fmt.Errorf("afssl: generate failed, %v", err)
		return
	}
	return
}
