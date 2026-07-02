package main

import (
	"log/slog"
	"os"

	"github.com/neoworks/auth/logging"
)

func setupLogger() *slog.Logger {
	logger := slog.New(logging.NewPrettyHandler(os.Stdout, slog.LevelDebug))

	slog.SetDefault(logger)

	return logger
}
