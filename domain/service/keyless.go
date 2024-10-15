package service

import (
	"context"
	"crypto"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"sort"
	"time"

	"edgeone-keyless-server/domain/entity"
	"edgeone-keyless-server/domain/repository"
	response "edgeone-keyless-server/infrastructure/constant"
	"edgeone-keyless-server/infrastructure/protocol/keyless"
	"edgeone-keyless-server/infrastructure/utils"

	"google.golang.org/protobuf/types/known/wrapperspb"
	"trpc.group/trpc-go/trpc-go/errs"
	"trpc.group/trpc-go/trpc-go/log"
)

// KeylessService implements repository.KeylessService.
type KeylessService struct {
	TlsConfig *tls.Config
	Config    *entity.Conf
	// During initialization, A will be imported first, and B will be used for updates, in a round-robin fashion
	KeyLessCert                *entity.KeyLessCert
	CurrentRequestActionMetric map[string]*entity.SSLRequestResult
}

// NewKeylessService creates a new KeylessService instance.
func NewKeylessService(tlsConfig *tls.Config, conf *entity.Conf) *KeylessService {
	return &KeylessService{
		TlsConfig:   tlsConfig,
		Config:      conf,
		KeyLessCert: entity.NewKeyLessCert(),
		CurrentRequestActionMetric: map[string]*entity.SSLRequestResult{
			entity.RSA_SIGN_RECORD:    entity.NewSSLRequestResult(),
			entity.RSA_DECRYPT_RECORD: entity.NewSSLRequestResult(),
			entity.RSA_ENCRYPT_RECORD: entity.NewSSLRequestResult(),
			entity.ECC_SIGN_RECORD:    entity.NewSSLRequestResult(),
			entity.ECC_DECRYPT_RECORD: entity.NewSSLRequestResult(),
			entity.ECC_ENCRYPT_RECORD: entity.NewSSLRequestResult(),
			entity.CERT_LOAD_RECORD:   entity.NewSSLRequestResult(),
		},
	}
}

var _ repository.KeylessService = (*KeylessService)(nil)

// KeylessQueryMetricInfo is a method of the KeylessService struct that queries metric information without using keys.
func (k *KeylessService) KeylessQueryMetricInfo(ctx context.Context,
	req *keyless.KeylessRequestReq,
) (*keyless.KeylessRequestResp, error) {
	// Output current business information
	// Current number of connections
	// Current total number of accesses
	// Current number of encryption, signing, decryption operations
	// Current time taken for encryption, signing, decryption
	// Current total number of successes and failures in encryption, signing, decryption
	// Current number of certificate loading operations
	var currentBusinessInfo string
	// Convert map keys to a slice
	keys := make([]string, 0, len(k.CurrentRequestActionMetric))
	for k := range k.CurrentRequestActionMetric {
		keys = append(keys, k)
	}

	// Sort keys
	sort.Strings(keys)

	// Output values in the map according to sorted keys
	for _, key := range keys {
		currentBusinessInfo += fmt.Sprintf("%s:%s ", key, k.CurrentRequestActionMetric[key].ToString())
	}

	return &keyless.KeylessRequestResp{
		RetCode: wrapperspb.Int32(response.KS_OK),
		Msg:     wrapperspb.String(currentBusinessInfo),
	}, nil
}

// KeylessRequest implements the repository.KeylessService interface.
// It handles keyless requests, logs records, and prepares responses.
func (k *KeylessService) KeylessRequest(ctx context.Context, req *keyless.KeylessRequestReq) (
	rsp *keyless.KeylessRequestResp, err error,
) {
	// Set log to include seq session id
	newLog := log.DefaultLogger
	if req.GetSeq() != nil {
		newLog = log.With(log.Field{Key: response.MSG_UUID_NAME, Value: req.GetSeq().GetValue()})
	}
	newLog.Infof("KeylessRequest :%+v", req)
	reqType := req.GetType().GetValue()
	newLog.Infof("KeylessRequest reqType :%+v", reqType)
	// Metric statistics
	k.CurrentRequestActionMetric[entity.SSLAlgoMetricMap[reqType]].TotalAccount()
	now := time.Now().UnixMilli()
	isOk := false
	defer func() {
		last := time.Now().UnixMilli()
		opCost := last - now
		newLog.Infof("now:%s , before: %s, cost(ms): %d, isok:%t", utils.TimeFormat(now/1000), utils.TimeFormat(last/1000),
			last-now, isOk)

		if !isOk {
			k.CurrentRequestActionMetric[entity.SSLAlgoMetricMap[reqType]].TotalFailureAccount()
		} else {
			k.CurrentRequestActionMetric[entity.SSLAlgoMetricMap[reqType]].TotalSuccessAccount()
		}
		k.CurrentRequestActionMetric[entity.SSLAlgoMetricMap[reqType]].AllCostCount(opCost)
	}()

	switch reqType {
	case entity.RSA_SIGN:
		rsp, err = k.signRequest(ctx, req, newLog)
		if err != nil {
			log.ErrorContextf(ctx, "sign request failed:%+v", err)
			break
		}
		isOk = true
	case entity.RSA_DECRYPT:
		rsp, err = k.decryptRequest(ctx, req, newLog)
		if err != nil {
			log.ErrorContextf(ctx, "decrypt request failed:%+v", err)
			break
		}
		isOk = true
	case entity.RSA_ENCRYPT:
		rsp, err = k.encryptRequest(ctx, req, newLog)
		if err != nil {
			log.ErrorContextf(ctx, "encrypt request failed:%+v", err)
			break
		}
		isOk = true
	case entity.ECC_SIGN:
		rsp, err = k.signRequest(ctx, req, newLog)
		if err != nil {
			log.ErrorContextf(ctx, "sign request failed:%+v", err)
			break
		}
		isOk = true
	case entity.ECC_DECRYPT:
		rsp, err = k.decryptRequest(ctx, req, newLog)
		if err != nil {
			log.ErrorContextf(ctx, "decrypt request failed:%+v", err)
			break
		}
		isOk = true
	case entity.ECC_ENCRYPT:
		rsp, err = k.encryptRequest(ctx, req, newLog)
		if err != nil {
			log.ErrorContextf(ctx, "encrypt request failed:%+v", err)
			break
		}
		isOk = true
	default:
		log.DebugContextf(ctx, "wrong req type")
		err = response.ErrWrongReqType
	}

	if !isOk {
		// Determine the type of data structure
		v, ok := err.(*errs.Error)
		rsp = &keyless.KeylessRequestResp{}
		if ok {
			rsp.RetCode = wrapperspb.Int32(int32(v.Code))
		} else {
			// If err is not of type *errs.Error, handle it according to the actual situation
			log.Errorf("unknow err:%+v", err)
			rsp.RetCode = wrapperspb.Int32(int32(response.KS_ERROR))
		}
		rsp.AlreadyCrypt = wrapperspb.Bool(false)
		rsp.Msg = wrapperspb.String(v.Msg)
	}

	return rsp, nil
}

// signRequest handles RSA signing requests.
func (k *KeylessService) signRequest(ctx context.Context, req *keyless.KeylessRequestReq,
	newLog log.Logger,
) (*keyless.KeylessRequestResp, error) {
	newLog.Infof("signRequest :%+v", utils.PrintJsonLog(req))
	ka, err := getKeyAgreement(ctx, req)
	if err != nil {
		log.ErrorContextf(ctx, "sign failed:%+v", err)
		return nil, err
	}
	cert, err := k.GetRightPrivateKey(req.GetCertSn().GetValue(), req.CertIssuer.GetValue(), newLog)
	if err != nil {
		log.ErrorContextf(ctx, "there's no pk in key consistent of certsn(%v) and certIssuer(%v) ",
			req.GetCertSn().GetValue(), req.CertIssuer.GetValue())

		return nil, err
	}
	data, err := ka.Sign(ctx, req.GetData().GetValue(), k.TlsConfig, &cert.PrivateKey,
		entity.IsRSAPSS(cert.PublicKey.SignatureAlgorithm))
	if err != nil {
		log.ErrorContextf(ctx, "sign failed:%+v", err)
		return nil, err
	}
	newLog.Infof("sign success")
	return &keyless.KeylessRequestResp{
		RetCode: wrapperspb.Int32(response.KS_OK),
		Data:    wrapperspb.Bytes(data),
	}, nil
}

// encryptRequest handles RSA encryption requests.
func (k *KeylessService) encryptRequest(ctx context.Context, req *keyless.KeylessRequestReq,
	newLog log.Logger,
) (*keyless.KeylessRequestResp, error) {
	newLog.Infof("encryptRequest :%+v", utils.PrintJsonLog(req))
	ka, err := getKeyAgreement(ctx, req)
	if err != nil {
		log.ErrorContextf(ctx, "encrypt failed:%+v", err)
		return nil, err
	}
	cert, err := k.GetRightPrivateKey(req.GetCertSn().GetValue(), req.CertIssuer.GetValue(), newLog)
	if err != nil {
		log.ErrorContextf(ctx, "there's no pk in key consistent of certsn(%v) and certIssuer(%v) ",
			req.GetCertSn().GetValue(), req.CertIssuer.GetValue())

		return nil, err
	}
	data, err := ka.Encrypt(ctx, req.GetData().GetValue(), k.TlsConfig, &cert.PrivateKey,
		int(req.GetPadding().GetValue()))
	if err != nil {
		log.ErrorContextf(ctx, "encrypt failed:%+v", err)
		return nil, err
	}

	newLog.Infof("encrypt success")
	return &keyless.KeylessRequestResp{
		RetCode: wrapperspb.Int32(response.KS_OK),
		Data:    wrapperspb.Bytes(data),
	}, nil
}

// decryptRequest handles RSA decryption requests.
func (k *KeylessService) decryptRequest(ctx context.Context, req *keyless.KeylessRequestReq,
	newLog log.Logger,
) (*keyless.KeylessRequestResp, error) {
	newLog.Infof("decryptRequest :%+v", utils.PrintJsonLog(req))
	ka, err := getKeyAgreement(ctx, req)
	if err != nil {
		log.ErrorContextf(ctx, "decrypt failed:%+v", err)
		return nil, err
	}
	cert, err := k.GetRightPrivateKey(req.GetCertSn().GetValue(), req.CertIssuer.GetValue(), newLog)
	if err != nil {
		log.ErrorContextf(ctx, "there's no pk in key consistent of certsn(%v) and certIssuer(%v) ",
			req.GetCertSn().GetValue(), req.CertIssuer.GetValue())

		return nil, err
	}
	data, err := ka.Decrypt(ctx, req.GetData().GetValue(), k.TlsConfig, &cert.PrivateKey,
		int(req.GetPadding().GetValue()))
	if err != nil {
		log.ErrorContextf(ctx, "decrypt failed:%+v", err)
		return nil, err
	}
	strData := base64.StdEncoding.EncodeToString(data)
	newLog.Infof("decrypt success data:%s", strData)
	return &keyless.KeylessRequestResp{
		RetCode: wrapperspb.Int32(response.KS_OK),
		Data:    wrapperspb.Bytes([]byte(strData)),
	}, nil
}

// getKeyAgreement retrieves the appropriate key agreement algorithm.
func getKeyAgreement(ctx context.Context, req *keyless.KeylessRequestReq) (repository.KeyAgreement, error) {
	keyAgreement, ok := entity.CipherSuites[(uint16(req.GetCertType().GetValue()))]
	if !ok {
		log.ErrorContextf(ctx, "algo(%d) of ssl is unsupported!", req.GetCertType().GetValue())
		return nil, response.ErrNotSupprotCipher
	}
	// Set default value
	sigType := crypto.MD5SHA1
	if req.GetSignType().GetValue() != 0 && req.GetType().GetValue() == entity.RSA_SIGN {
		sigType, ok = entity.NidToHash[int(req.GetSignType().GetValue())]
		if !ok {
			log.ErrorContextf(ctx, "signType(%d) of ssl is unsupported!", req.GetSignType().GetValue())
			return nil, response.ErrNotSupprotSignType
		}
	}
	return keyAgreement.Ka(tls.VersionTLS10, sigType), nil
}

// KeylessReloadCerts implements repository.KeylessService.
func (k *KeylessService) KeylessReloadCerts(ctx context.Context,
	req *keyless.KeylessRequestReq,
) (*keyless.KeylessRequestResp, error) {
	currPath, err := utils.GetExeFilePath()
	if err != nil {
		log.ErrorContextf(ctx, "get current path failed")
		return nil, err
	}
	if err := k.LoadCerts(currPath+k.Config.Config.PrivateKeyPath, false, log.DefaultLogger); err != nil {
		log.ErrorContextf(ctx, "load certs failed:%v", err)
		return nil, err
	}

	return &keyless.KeylessRequestResp{}, nil
}
