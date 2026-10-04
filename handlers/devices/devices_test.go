package devices_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/auth/handlers/devices"
	"github.com/neoworks/auth/handlers/handlertest"
	"github.com/neoworks/auth/storage/database"
	"github.com/neoworks/auth/storage/database/dbtest"
)

func TestDeviceListAndRevoke(t *testing.T) {
	store := dbtest.New(t)
	deviceHandler := devices.NewHandler(store)
	router := handlertest.NewAuthenticated(func(router chi.Router) { deviceHandler.RegisterAuthenticated(router) })
	user := handlertest.CreateUser(t, store)
	device, err := store.RegisterDevice(context.Background(), user.UserID, &database.RegisterDeviceParams{Name: "Laptop", Kind: database.DeviceKindBrowser})
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	var list struct {
		Devices []database.Device `json:"devices"`
	}
	handlertest.Decode(t, router.Do(t, user, "GET", "/api/v1/devices", nil, nil), &list)
	if len(list.Devices) != 1 || list.Devices[0].Kind != "browser" {
		t.Fatalf("list: %+v", list)
	}
	if response := router.Do(t, user, "DELETE", "/api/v1/devices/"+device.ID, nil, nil); response.Code != http.StatusNoContent {
		t.Fatalf("revoke: %d", response.Code)
	}
}
