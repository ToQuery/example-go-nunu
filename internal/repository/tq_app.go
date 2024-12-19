package repository

type TqAppRepository interface {
	//GetTqApp(ctx context.Context, id int64) (*model.TqApp, error)
}

func NewTqAppRepository(
	repository *Repository,
) TqAppRepository {
	return &tqAppRepository{
		Repository: repository,
	}
}

type tqAppRepository struct {
	*Repository
}

//func (r *tqAppRepository) GetTqApp(ctx context.Context, id int64) (*model.TqApp, error) {
//	var tqApp model.TqApp
//	return &tqApp, nil
//}
