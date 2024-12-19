package service

import (
	"example-nunu/internal/repository"
)

type TqAppService interface {
	//GetTqApp(ctx context.Context, id int64) (*model.TqApp, error)
}

func NewTqAppService(
	service *Service,
	tqAppRepository repository.TqAppRepository,
) TqAppService {
	return &tqAppService{
		Service:         service,
		tqAppRepository: tqAppRepository,
	}
}

type tqAppService struct {
	*Service
	tqAppRepository repository.TqAppRepository
}

//func (s *tqAppService) GetTqApp(ctx context.Context, id int64) (*model.TqApp, error) {
//	return s.tqAppRepository.GetTqApp(ctx, id)
//}
