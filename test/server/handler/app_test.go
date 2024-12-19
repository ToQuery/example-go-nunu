package handler

import (
	v1 "example-go-nunu/api/v1"
	"example-go-nunu/internal/handler"
	"example-go-nunu/test/mocks/service"
	"net/http"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestTqAppHandler_TqAppIndex(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockTqAppService := mock_service.NewMockTqAppService(ctrl)
	mockTqAppService.EXPECT().TqAppIndex(gomock.Any()).Return(&v1.AppIndex{
		Name: "",
		Info: map[string]interface{}{
			"0x00": "Hello World!",
		},
	}, nil)

	appHandler := handler.NewTqAppHandler(hdl, mockTqAppService)
	router.GET("/v1/app/index", appHandler.TqAppIndex)

	resp := performRequest(router, "GET", "/v1/app/index", nil)

	assert.Equal(t, resp.Code, http.StatusOK)
	// Add assertions for the response body if needed
}
