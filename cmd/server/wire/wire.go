//go:build wireinject
// +build wireinject

package wire

import (
	"example-go-nunu/internal/handler"
	"example-go-nunu/internal/repository"
	"example-go-nunu/internal/server"
	"example-go-nunu/internal/service"
	"example-go-nunu/pkg/app"
	"example-go-nunu/pkg/jwt"
	"example-go-nunu/pkg/log"
	"example-go-nunu/pkg/server/http"
	"example-go-nunu/pkg/sid"
	"github.com/google/wire"
	"github.com/spf13/viper"
)

var repositorySet = wire.NewSet(
	repository.NewDB,
	//repository.NewRedis,
	repository.NewRepository,
	repository.NewTransaction,
	repository.NewUserRepository,
	repository.NewTqAppRepository,
	repository.NewTqDeveloperRepository,
)

var serviceSet = wire.NewSet(
	service.NewService,
	service.NewUserService,
	service.NewTqAppService,
	service.NewTqDeveloperService,
)

var handlerSet = wire.NewSet(
	handler.NewHandler,
	handler.NewUserHandler,
	handler.NewTqAppHandler,
	handler.NewTqDeveloperHandler,
)

var serverSet = wire.NewSet(
	server.NewHTTPServer,
	server.NewJob,
)

// build App
func newApp(
	httpServer *http.Server,
	job *server.Job,
) *app.App {
	return app.NewApp(
		app.WithServer(httpServer, job),
		app.WithName("example-go-nunu"),
	)
}

func NewWire(*viper.Viper, *log.Logger) (*app.App, func(), error) {
	panic(wire.Build(
		repositorySet,
		serviceSet,
		handlerSet,
		serverSet,
		sid.NewSid,
		jwt.NewJwt,
		newApp,
	))
}
