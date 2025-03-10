package service

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"trpc.group/trpc-go/trpc-go/log"

	"edgeone-keyless-server/domain/entity"
	response "edgeone-keyless-server/infrastructure/constant"
	"edgeone-keyless-server/infrastructure/utils"
)

// LoadCerts loads certificates and private keys from the specified directory.
func (k *KeylessService) LoadCerts(keyPath string, first bool, newLog log.Logger) error {
	k.CurrentRequestActionMetric[entity.CERT_LOAD_RECORD].TotalAccount()
	now := time.Now().UnixMilli()
	isOk := false
	// metric statistics
	defer func() {
		last := time.Now().UnixMilli()
		opCost := last - now
		newLog.Infof("now:%s , before: %s, cost(ms): %d", utils.TimeFormat(now/1000), utils.TimeFormat(last/1000), last-now)
		if !isOk {
			k.CurrentRequestActionMetric[entity.CERT_LOAD_RECORD].TotalFailureAccount()
		} else {
			k.CurrentRequestActionMetric[entity.CERT_LOAD_RECORD].TotalSuccessAccount()
		}
		k.CurrentRequestActionMetric[entity.CERT_LOAD_RECORD].AllCostCount(opCost)
	}()
	// Read all certificate and private key files in the directory
	certificateFiles, err := os.ReadDir(keyPath)
	if err != nil {
		newLog.Errorf("read key path failed: %v", err)
		return err
	}

	tempHostKeyMap := make(map[string]*entity.CertificateInfo, len(certificateFiles))

	// Iterate over each file in the directory
	for _, file := range certificateFiles {
		if !file.IsDir() {
			filePath := filepath.Join(keyPath, file.Name())
			fileContent, err := os.ReadFile(filePath)
			if err != nil {
				newLog.Errorf("read file failed: %v", err)
				continue
			}
			// get key
			key := utils.GetFileName(file.Name())
			if len(key) == 0 {
				newLog.Errorf("file is wrong: %v", filePath)
				continue
			}
			// If it is a crt or pem file, treat it as a public key
			if strings.HasSuffix(file.Name(), entity.PUB_SUFFIX) || strings.HasSuffix(file.Name(), entity.CERT_PEM_SUFFIX) {
				newLog.Infof("parse public file path:%s", filePath)
				certInfo, err := parseCertificate(fileContent)
				if err != nil {
					newLog.Errorf("parse pubkey failed: %v", err)
					continue
				}
				// Print signature algorithm
				newLog.Infof("sigAlgStr:%v", certInfo.SignatureAlgorithm.String())

				v, ok := tempHostKeyMap[key]
				if !ok {
					tempHostKeyMap[key] = &entity.CertificateInfo{
						RawPublicKey: fileContent,
						PublicKey:    certInfo,
						CertName:     utils.GetFileName(file.Name()),
					}
				} else {
					if v.RawPublicKey == nil || len(v.RawPublicKey) == 0 {
						v.PublicKey = certInfo
						v.RawPublicKey = fileContent
					}
				}
				continue
			}
			// Try to parse as a private key
			if strings.HasSuffix(file.Name(), entity.PK_SUFFIX) {
				newLog.Infof("parse private file path:%s", filePath)
				privateKey, err := parsePrivateKey(fileContent, newLog)
				if err == nil {
					v, ok := tempHostKeyMap[key]
					if !ok {
						tempHostKeyMap[key] = &entity.CertificateInfo{
							RawPrivateKey: fileContent,
							PrivateKey:    privateKey,
							CertName:      utils.GetFileName(file.Name()),
						}
					} else {
						if v.RawPrivateKey == nil || len(v.RawPrivateKey) == 0 {
							v.PrivateKey = privateKey
							v.RawPrivateKey = fileContent
						}
					}
					continue
				} else {
					newLog.Errorf("parse private key failed: %v", err)
				}
			}
			newLog.Errorf("parse file failed or unsupported: %s", filePath)
		}
	}

	// Update to currentKeyMap, clear the original certificate information and reload
	// The purpose of using a temporary variable is to shorten the time to lock the global variable, concentrated here for
	// replacement
	// Get the write lock for the "B" block certinfo
	updateCertInfo := k.KeyLessCert.GetUpdateOne()
	if updateCertInfo.DataLock.TryLock(entity.TIME_WAIT_RW * time.Second) {
		defer updateCertInfo.DataLock.Unlock()
		updateCertInfo.GetCertInfo().HostKeyMap = tempHostKeyMap
		tempUniqKeyMap := make(map[string]*entity.CertificateInfo, len(tempHostKeyMap))
		updateCertInfo.GetCertInfo().UniqKeyMap = tempUniqKeyMap
		for key, v := range updateCertInfo.GetCertInfo().HostKeyMap {
			rI, err := parseIssuer(v.PublicKey.RawIssuer)
			if err != nil {
				newLog.Errorf("parse issuer failed: %v", err)
				continue
			}
			uniqKey := utils.GetCertKey(getCertSn(v.PublicKey.SerialNumber.Text(entity.SN_2_STRING_HEX)),
				rDNSequence2String(*rI))
			newLog.Infof("load cert key:%v, isser:%s ---- %s", key, issuer2StringWithoutExt(&v.PublicKey.Issuer),
				rDNSequence2String(*rI))
			newLog.Infof("load cert key:%v, unikey:%s", key, uniqKey)
			updateCertInfo.GetCertInfo().UniqKeyMap[uniqKey] = v
		}
		// If it's the first time, update both A and B
		if first {
			k.KeyLessCert.SyncAB()
		}
		// Update the current latest status
		k.KeyLessCert.SetCurrent()
		// metric
		isOk = true
	} else {
		// Failed to acquire lock, update failed
		newLog.Errorf("try lock failed!")
	}

	newLog.Infof("update host count(%d) ", len(updateCertInfo.GetCertInfo().HostKeyMap))
	newLog.Infof("update uniq count(%d) ", len(updateCertInfo.GetCertInfo().UniqKeyMap))
	newLog.Infof("certa host count(%d) and  certb host count(%d)", len(k.KeyLessCert.CertInfoA.GetCertInfo().HostKeyMap),
		len(k.KeyLessCert.CertInfoB.GetCertInfo().HostKeyMap))
	newLog.Infof("update cert info finished, current cert is  :%+v", k.KeyLessCert.GetCurrentFlag())
	return nil
}

// parseCertificate parses a certificate from PEM encoded data.
func parseCertificate(cert []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(cert)
	if block == nil {
		return nil, response.ErrWrongPublic
	}

	certInfo, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return certInfo, nil
}

// parsePrivateKey parses a private key from PEM encoded data.
func parsePrivateKey(privateKeyFile []byte, newLog log.Logger) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(privateKeyFile)
	if block == nil {
		return nil, response.ErrWrongPK
	}
	newLog.Infof("pk type:%v", block.Type)
	switch block.Type {
	case response.PRIVAETE_KEY_ECC:
		newLog.Infof("EC PRIVATE KEY")
		return x509.ParseECPrivateKey(block.Bytes)
	case response.PRIVAETE_KEY_RSA:
		newLog.Infof("RSA PRIVATE KEY")
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case response.PRIVAETE_KEY:
		newLog.Infof("PRIVATE KEY")
		if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			switch key := key.(type) {
			case *rsa.PrivateKey:
				newLog.Infof("RSA PRIVATE KEY")
				return key, nil
			case *ecdsa.PrivateKey:
				newLog.Infof("EC PRIVATE KEY")
				return key, nil
			default:
				newLog.Errorf("unknow pk type:%v", block.Type)
				return nil, response.ErrUnknownPK
			}
		}
	default:
		newLog.Errorf("unknow pk type:%v", block.Type)
		return nil, response.ErrUnknownPK
	}
	return nil, nil
}

// parsePrivateKeyII parses a private key from DER encoded data.
func parsePrivateKeyII(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return key, nil
		default:
			return nil, response.ErrUnknownPK
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, response.ErrWrongPK
}

// GetRightPrivateKey retrieves the correct private key based on the certificate serial number and issuer.
func (k *KeylessService) GetRightPrivateKey(certSn, certIssuer string, newLog log.Logger) (*entity.CertificateInfo,
	error,
) {
	// Get read lock
	currentCertInfoPtr := k.KeyLessCert.GetCurrentOne()
	if currentCertInfoPtr.DataLock.TryRLock(entity.TIME_WAIT_RW * time.Second) {
		defer currentCertInfoPtr.DataLock.RUnlock()
		uniqKey := utils.GetCertKey(getCertSn(certSn), certIssuer)
		v, ok := currentCertInfoPtr.GetCertInfo().UniqKeyMap[uniqKey]
		if !ok {
			newLog.Errorf("there's no pk in key consistent of certsn(%v) and certIssuer(%v), uniqKey:%s ,keys:%+v",
				getCertSn(certSn), certIssuer, uniqKey, utils.GetKeys(currentCertInfoPtr.GetCertInfo().UniqKeyMap))

			return nil, response.ErrPKNotFound
		}
		return v, nil
	} else {
		newLog.Errorf("try r lock failed")
		return nil, response.ErrRLockFailed
	}
}

func issuer2String(issuer *pkix.Name) string {
	var rdns pkix.RDNSequence
	// If there are no ExtraNames, surface the parsed value (all entries in
	// Names) instead.
	if issuer.ExtraNames == nil {
		for _, atv := range issuer.Names {
			t := atv.Type
			if len(t) == 4 && t[0] == 2 && t[1] == 5 && t[2] == 4 {
				switch t[3] {
				case 3, 5, 6, 7, 8, 9, 10, 11, 17:
					// These attributes were already parsed into named fields.
					continue
				}
			}
			// Place non-standard parsed values at the beginning of the sequence
			// so they will be at the end of the string. See Issue 39924.
			rdns = append(rdns, []pkix.AttributeTypeAndValue{atv})
		}
	}
	rdns = append(rdns, issuer.ToRDNSequence()...)
	return rDNSequence2String(rdns)
}

func issuer2StringWithoutExt(issuer *pkix.Name) string {
	return rDNSequence2String(issuer.ToRDNSequence())
}

func rDNSequence2String(r pkix.RDNSequence) string {
	s := ""
	for i := 0; i < len(r); i++ {
		rdn := (r)[i]
		if i > 0 {
			s += ", "
		}
		for j, tv := range rdn {
			if j > 0 {
				s += "+"
			}

			oidString := tv.Type.String()
			typeName, ok := entity.AttributeTypeNames[oidString]

			if !ok {
				derBytes, err := asn1.Marshal(tv.Value)
				if err == nil {
					s += oidString + "=#" + hex.EncodeToString(derBytes)
					continue // No value escaping necessary.
				}

				typeName = oidString
			}

			valueString := fmt.Sprint(tv.Value)
			s += typeName + "=" + string(valueString)
		}
	}

	return s
}

func getCertSn(sn string) string {
	newSn := strings.ToUpper(sn)
	newSn = utils.TrimLeadingZeros(newSn)
	return newSn
}

// parseIssuer parses the issuer field from a certificate.
func parseIssuer(issuer []byte) (*pkix.RDNSequence, error) {
	var rdnSequence pkix.RDNSequence
	_, err := asn1.Unmarshal(issuer, &rdnSequence)
	if err != nil {
		log.Fatalf("failed to unmarshal RawIssuer: %v", err)
		return nil, err
	}
	return &rdnSequence, nil
}
