package repository

import (
	"context"
	"example-go-nunu/internal/model"
)

type TqDeveloperRepository interface {
	GetTqDeveloper(ctx context.Context, id int64) (*model.TqDeveloper, error)
}

func NewTqDeveloperRepository(
	repository *Repository,
) TqDeveloperRepository {
	return &tqDeveloperRepository{
		Repository: repository,
	}
}

type tqDeveloperRepository struct {
	*Repository
}

func (r *tqDeveloperRepository) GetTqDeveloper(ctx context.Context, id int64) (*model.TqDeveloper, error) {
	var tqDeveloper model.TqDeveloper

	return &tqDeveloper, nil
}
