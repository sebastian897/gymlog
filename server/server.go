package main

import (
	// Note: Also remove the 'os' import.

	"context"
	"database/sql"
	"errors"
	"fmt"
	"gymlog/common"
	"gymlog/templates"
	"net/http"
	"net/mail"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"

	"github.com/go-sql-driver/mysql"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
)

var (
	store sessions.Store
	db    *sql.DB
	dbctx = context.Background()
)

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 11)
	return string(bytes), err
}

// VerifyPassword verifies if the given password matches the stored hash.
func VerifyPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

const (
	GRASS    = 1
	NILVALUE = -1
)

func Login(email string, password string, sess *sessions.Session) error {
	var password_hash string
	var id int
	err := db.QueryRowContext(dbctx, "SELECT id,password FROM user WHERE email = ?", email).Scan(&id, &password_hash)
	if err == sql.ErrNoRows || !VerifyPassword(password, password_hash) {
		fmt.Printf("Invalid login %s\n", email)
		return fmt.Errorf("email or password invalid")
	} else if err != nil {
		panic(err)
	}
	sess.Values["loggedInUserId"] = id
	fmt.Printf("Valid login id = %d\n", id)
	return nil
}

func Register(email string, password string, name string, sess *sessions.Session) error {
	password_hash, _ := HashPassword(password)
	var id int64
	if !validEmail(email) {
		return fmt.Errorf("email invalid")
	}
	if err := validatePassword(password); err != nil {
		return err
	}
	if err := validateName(name); err != nil {
		return err
	}
	insertResult, err := db.ExecContext(dbctx, "INSERT into user(name,email,password) values(?,?,?)", name, email, password_hash)
	if err != nil {
		return fmt.Errorf("failed to create account")
	}
	id, _ = insertResult.LastInsertId()
	sess.Values["loggedInUserId"] = int(id)
	fmt.Printf("Valid login id = %d\n", id)
	return nil
}

func validEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

func validatePassword(password string) error {
	if len(password) < 8 {
		return fmt.Errorf("password too short (min 8 characters)")
	}
	return nil
}

func validateName(name string) error {
	if len(name) < 3 {
		return fmt.Errorf("name too short (min 3 characters)")
	}
	return nil
}

func GetSession(r *http.Request) *sessions.Session {
	session, err := store.Get(r, "gymlogTrading")
	if err != nil {
		panic(err)
	}
	return session
}

func GetLoggedInUser(w http.ResponseWriter, r *http.Request, session *sessions.Session) (common.User, error) {
	if session.Values["loggedInUserId"] == nil {
		http.Redirect(w, r, "/seb/gymlog/login", http.StatusFound)
		return common.User{}, fmt.Errorf("Not Logged In, Redirect to login")
	}
	user_id := session.Values["loggedInUserId"].(int)
	var usr common.User
	err := db.QueryRowContext(dbctx, "SELECT id,name,password,email,admin FROM user WHERE id = ?", user_id).Scan(&usr.Id, &usr.Name, &usr.Password, &usr.Email, &usr.Admin)
	if err != nil {
		http.Redirect(w, r, "/seb/gymlog/login", http.StatusFound)
		session.Values["loggedInUserId"] = nil
		session.Save(r, w)
	}
	return usr, err
}
func handleRoot(w http.ResponseWriter, r *http.Request) {
	component := templates.Root()
	component.Render(context.Background(), w)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	session := GetSession(r)
	var err error
	var errmsg string
	if r.URL.Query().Get("action") == "login" {
		u := r.FormValue("email")
		p := r.FormValue("password")
		err = Login(u, p, session)
		if err != nil {
			errmsg = err.Error()
		}
	} else if r.URL.Query().Get("action") == "logout" {
		session.Values["loggedInUserId"] = nil
	}
	err = session.Save(r, w)
	if err != nil {
		panic(err)
	}
	if session.Values["loggedInUserId"] != nil {
		http.Redirect(w, r, "/seb/gymlog/track", http.StatusFound)
		return
	}
	component := templates.Login(errmsg)
	component.Render(context.Background(), w)
}

func handleRegister(w http.ResponseWriter, r *http.Request) {
	session := GetSession(r)
	var err error
	var errmsg string
	if r.URL.Query().Get("action") == "register" {
		e := r.FormValue("email")
		n := r.FormValue("name")
		p := r.FormValue("password")
		err = Register(e, p, n, session)
		if err != nil {
			errmsg = err.Error()
		}

	}
	err = session.Save(r, w)
	if err != nil {
		fmt.Println("session.save error = ", err)
	}
	if session.Values["loggedInUserId"] != nil {
		http.Redirect(w, r, "/seb/gymlog/track", http.StatusFound)
		return
	}
	component := templates.Register(errmsg)
	component.Render(context.Background(), w)
}

func handleTrack(w http.ResponseWriter, r *http.Request) {
	session := GetSession(r)
	usr, err := GetLoggedInUser(w, r, session)
	if err != nil {
		fmt.Printf("getLoggedInUser returned an error %s", err)
		return
	}
	if r.URL.Query().Get("action") == "save" {
		var exLog common.ExerciseLog
		exLog.ExerciseId, _ = strconv.Atoi(r.FormValue("exercise_id"))
		exLog.Date = time.Now()
		exLog.Weight, _ = strconv.ParseFloat(r.FormValue("weight"), 64)
		exLog.Reps, _ = strconv.Atoi(r.FormValue("reps"))
		exLog.Sets, _ = strconv.Atoi(r.FormValue("sets"))
		fmt.Printf("exLog.ExerciseId, exLog.Weight, exLog.Reps, exLog.Sets %d %f %d %d ", exLog.ExerciseId, exLog.Weight, exLog.Reps, exLog.Sets)
		if exLog.ExerciseId > 0 && exLog.Weight > 0 && exLog.Reps > 0 && exLog.Sets > 0 {
			_, err := db.ExecContext(dbctx, "insert into exercise_log(user_id,exercise_id,date,weight,reps,sets) values(?,?,?,?,?,?)", usr.Id, exLog.ExerciseId, exLog.Date, exLog.Weight, exLog.Reps, exLog.Sets)
			if err != nil {
				panic(err)
			}
			http.Redirect(w, r, "/seb/gymlog/track", http.StatusFound)
		}
	}
	exercises, _ := getExercises()
	component := templates.Track(usr, exercises)
	component.Render(context.Background(), w)
}

func getExercises() ([]common.Exercise, error) {
	rows, err := db.QueryContext(dbctx, "select id,name from exercise order by name")
	if err != nil {
		panic(err)
	}
	exercises := make([]common.Exercise, 0)

	defer rows.Close()
	for rows.Next() {
		var ex common.Exercise
		if err := rows.Scan(&ex.Id, &ex.Name); err != nil {
			panic(err)
		}
		_ = db.QueryRowContext(dbctx, `SELECT COUNT(DISTINCT user_id) FROM exercise_log WHERE exercise_id = ?`, ex.Id).Scan(&ex.Users)
		exercises = append(exercises, ex)
	}
	return exercises, err
}

func getCompletedExercises(usr *common.User) []common.Exercise {
	rows, err := db.QueryContext(dbctx, "SELECT distinct e.id, e.name FROM exercise_log el, exercise e WHERE el.exercise_id = e.id and el.user_id = ? order by name", usr.Id)
	if err != nil {
		panic(err)
	}
	exercises := make([]common.Exercise, 0)
	defer rows.Close()
	for rows.Next() {
		var ex common.Exercise
		if err := rows.Scan(&ex.Id, &ex.Name); err != nil {
			panic(err)
		}
		_ = db.QueryRowContext(dbctx, `SELECT COUNT(DISTINCT user_id) FROM exercise_log WHERE exercise_id = ?`, ex.Id).Scan(&ex.Users)
		exercises = append(exercises, ex)
	}
	return exercises
}

func getLoggedWeights(usr *common.User, exercise_id int) []int {
	rows, err := db.QueryContext(dbctx, "SELECT distinct weight FROM exercise_log WHERE exercise_id = ? and user_id = ? order by weight desc", exercise_id, usr.Id)
	if err != nil {
		panic(err)
	}

	weights := make([]int, 0)
	defer rows.Close()
	for rows.Next() {
		var w int
		if err := rows.Scan(&w); err != nil {
			panic(err)
		}
		weights = append(weights, w)
	}
	return weights
}

func getExerciseChart(usr common.User, exerise_id int, weight int) common.RepsLog {
	rows, err := db.QueryContext(dbctx, "SELECT el.date,el.reps FROM exercise_log el WHERE el.weight = ? and el.exercise_id = ? and el.user_id = ? order by date", weight, exerise_id, usr.Id)
	if err != nil {
		panic(err)
	}

	var chart common.RepsLog
	defer rows.Close()
	for rows.Next() {
		var date time.Time
		var rep int
		if err := rows.Scan(&date, &rep); err != nil {
			panic(err)
		}
		chart.Reps = append(chart.Reps, rep)
		chart.Dates = append(chart.Dates, date)
	}
	return chart
}

func getFormInt(formName string, defaultValue int, r *http.Request) int {
	num, err := strconv.Atoi(r.FormValue(formName))
	if err != nil {
		num = defaultValue
	}
	return num
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	session := GetSession(r)
	usr, err := GetLoggedInUser(w, r, session)
	if err != nil {
		return
	}

	var exercise_id = NILVALUE
	exs := getCompletedExercises(&usr)
	if len(exs) != 0 {
		exercise_id = getFormInt("exercise_id", exs[0].Id, r)
	}

	var weight = NILVALUE
	wts := getLoggedWeights(&usr, exercise_id)
	if len(exs) != 0 {
		weight = getFormInt("weight", wts[0], r)
	}

	var chart common.RepsLog
	if exercise_id > -1 && weight > -1 {
		chart = getExerciseChart(usr, exercise_id, weight)

	}

	component := templates.Home(usr, exs, exercise_id, wts, weight, chart)
	component.Render(context.Background(), w)
}

func handleExercise(w http.ResponseWriter, r *http.Request) {
	session := GetSession(r)
	usr, err := GetLoggedInUser(w, r, session)
	if err != nil {
		return
	}
	if r.URL.Query().Get("action") == "save" {
		var ex common.Exercise
		ex.Name = r.FormValue("name")
		_, err := db.ExecContext(dbctx, "insert into exercise(name) values(?)", ex.Name)
		if err != nil {
			panic(err)
		}

		http.Redirect(w, r, "/seb/gymlog/exercise", http.StatusFound)
	} else if r.URL.Query().Get("action") == "delete" {
		id, _ := strconv.Atoi(r.FormValue("exercise_id"))
		_, err := db.ExecContext(dbctx, "delete from exercise where id = ?", id)
		if err != nil {
			if merr, ok := err.(*mysql.MySQLError); ok && merr.Number == 1451 { // fk contraint
				http.Redirect(w, r, "/seb/gymlog/exercise", http.StatusFound)
			} else {
				panic(err)
			}
		}
	}

	exercises, _ := getExercises()
	component := templates.Exercise(usr, exercises)
	component.Render(context.Background(), w)
}

func main() {
	var err error
	fileStore := sessions.NewFilesystemStore("sess", []byte("MySecret"))
	fileStore.Options = &sessions.Options{
		Path:     "/seb/gymlog/",
		Domain:   "",
		MaxAge:   3600,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
	store = fileStore // global interface

	err = godotenv.Load()
	if err != nil {
		panic(err)
	}

	db, err = sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s)/%s?parseTime=true",
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASS"),
		os.Getenv("DB_HOST"),
		os.Getenv("DB_NAME")))
	if err != nil {
		panic(err)
	}
	if err = db.Ping(); err != nil {
		panic(err)
	}
	db.SetConnMaxLifetime(time.Minute * 3)
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(10)

	http.HandleFunc("/seb/gymlog/", handleRoot)
	http.HandleFunc("/seb/gymlog/track", handleTrack)
	http.HandleFunc("/seb/gymlog/login", handleLogin)
	http.HandleFunc("/seb/gymlog/register", handleRegister)
	http.HandleFunc("/seb/gymlog/home", handleHome)
	http.HandleFunc("/seb/gymlog/exercise", handleExercise)

	serverUrl := os.Getenv("SERVER_URL")
	fmt.Printf("Listening on %s\n", serverUrl)
	err = http.ListenAndServe(serverUrl, nil)
	if errors.Is(err, http.ErrServerClosed) {
		fmt.Printf("server closed\n")
	} else if err != nil {
		fmt.Printf("error starting server: %s\n", err)
		os.Exit(1)
	}
}
