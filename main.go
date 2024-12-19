package main

import (
	"crypto/rand"
	"crypto/tls"

	"edgeone-keyless-server/domain/entity"
	"edgeone-keyless-server/domain/service"
	"edgeone-keyless-server/infrastructure/constant"
	response "edgeone-keyless-server/infrastructure/constant"
	"edgeone-keyless-server/infrastructure/protocol/keyless"
	"edgeone-keyless-server/infrastructure/utils"

	"gopkg.in/yaml.v2"
	trpc "trpc.group/trpc-go/trpc-go"
	_ "trpc.group/trpc-go/trpc-go/client"
	"trpc.group/trpc-go/trpc-go/config"
	"trpc.group/trpc-go/trpc-go/log"
	"trpc.group/trpc-go/trpc-go/plugin"
)

// Conf defines the configuration content

// InitConf initializes user configuration information
func InitConf() (*entity.Conf, error) {
	// Load local configuration
	rootPath, _ := utils.GetExeFilePath()
	conf, err := config.Load(rootPath + entity.KEYLESS_CONFIG_PATH)
	if err != nil {
		log.Errorf("load config failed")
		return nil, response.ErrParseConfig
	}

	keylessConf := &entity.KeylessConfig{}
	if err = yaml.Unmarshal(conf.Bytes(), &keylessConf); err != nil {
		return nil, response.ErrParseConfig
	}
	log.Infof("config is :%+v", keylessConf)
	if keylessConf.Version == "" {
		keylessConf.Version = constant.VERSION
	}
	return &entity.Conf{Config: keylessConf}, nil
}

func main() {
	// Note: plugin.Register must be executed before trpc.NewServer
	plugin.Register("custom", log.DefaultLogFactory)

	s := trpc.NewServer()
	// Set log format
	log.SetLogger(log.Get("custom"))
	// Initialize configuration
	conf, err := InitConf()
	if err != nil {
		log.Errorf("init failed:%v", err)
		return
	}

	tlsConfig := &tls.Config{
		Rand: rand.Reader,
	}
	currPath, err := utils.GetExeFilePath()
	if err != nil {
		log.Errorf("get current path failed")
		return
	}
	keylessServer := service.NewKeylessService(tlsConfig, conf)

	// Load certificates
	err = keylessServer.LoadCerts(currPath+conf.Config.PrivateKeyPath, true, log.DefaultLogger)
	if err != nil {
		log.Errorf("load certs failed:%v", err)
		return
	}

	// HTTP service for local calls
	keyless.RegisterKeylessServiceService(s.Service(constant.HTTP_SERVER), keylessServer)
	// HTTPS service for remote calls
	keyless.RegisterKeylessServiceService(s.Service(constant.HTTPS_SERVER), keylessServer)
	log.Info(s.Serve())

}
