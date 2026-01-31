package common

import (
	"time"
)

type Exercise struct {
	Id   int
	Name string
}

type ExerciseLog struct {
	Id         int
	ExerciseId int
	UserId     int
	Date       time.Time
	Weight     float64
	Reps       int
	Sets       int
}

type User struct {
	Id       int
	Name     string
	Email    string
	Password string
	Admin    bool
}
