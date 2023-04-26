package db

import (
	"github.com/rs/zerolog/log"
)

func Configuration() {
	db, err := Setup()

	if err != nil {
		log.Error().Msg("An error occurs traying to connect to the database")
		return
	}

	migration(db)
}
