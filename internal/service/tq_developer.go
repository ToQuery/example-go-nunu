package service

import (
	"context"
	"example-go-nunu/internal/model"
	"example-go-nunu/internal/repository"
)

type TqDeveloperService interface {
	GetTqDeveloper(ctx context.Context, id int64) (*model.TqDeveloper, error)
}

func NewTqDeveloperService(
	service *Service,
	tqDeveloperRepository repository.TqDeveloperRepository,
) TqDeveloperService {
	return &tqDeveloperService{
		Service:               service,
		tqDeveloperRepository: tqDeveloperRepository,
	}
}

type tqDeveloperService struct {
	*Service
	tqDeveloperRepository repository.TqDeveloperRepository
}

func (s *tqDeveloperService) GetTqDeveloper(ctx context.Context, id int64) (*model.TqDeveloper, error) {
	return s.tqDeveloperRepository.GetTqDeveloper(ctx, id)
}
