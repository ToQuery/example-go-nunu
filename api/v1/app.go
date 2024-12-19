package v1

type AppIndex struct {
	Name string                 `json:"name"`
	Info map[string]interface{} `json:"info"`
}
