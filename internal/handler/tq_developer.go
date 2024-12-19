package handler

import (
	"example-go-nunu/internal/service"
	"github.com/gin-gonic/gin"
)

type TqDeveloperHandler struct {
	*Handler
	tqDeveloperService service.TqDeveloperService
}

func NewTqDeveloperHandler(
	handler *Handler,
	tqDeveloperService service.TqDeveloperService,
) *TqDeveloperHandler {
	return &TqDeveloperHandler{
		Handler:            handler,
		tqDeveloperService: tqDeveloperService,
	}
}

func (h *TqDeveloperHandler) GetTqDeveloper(ctx *gin.Context) {

}
