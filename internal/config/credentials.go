package config

import "github.com/pixingzoudaiyuexing/goedge-ip-cert/internal/goedge"

type GoEdgeCredentials struct {
	Config GoEdge
}

func (s GoEdgeCredentials) Credentials() (goedge.Credentials, error) {
	id, err := s.Config.AccessKeyID.Load()
	if err != nil {
		return goedge.Credentials{}, err
	}
	key, err := s.Config.AccessKey.Load()
	if err != nil {
		return goedge.Credentials{}, err
	}
	return goedge.Credentials{IdentityType: s.Config.IdentityType, AccessKeyID: id, AccessKey: key}, nil
}
