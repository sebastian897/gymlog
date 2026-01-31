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

func getResourceQuantity(user_id int, resource_id int) int {
	var quantity int = 0
	err := db.QueryRowContext(dbctx, "SELECT quantity FROM inventory_item WHERE user_id = ? and resource_id = ?", user_id, resource_id).Scan(&quantity)
	if err == sql.ErrNoRows {
		_, err2 := db.ExecContext(dbctx, "insert into inventory_item(user_id,resource_id,quantity) values(?,?,?)", user_id, resource_id, quantity)
		if err2 != nil {
			panic(err2)
		}
	} else if err != nil {
		panic(err)
	}
	return quantity
}

const (
	GRASS     = 1
	serverUrl = "127.0.0.1:8080"
)

func buyGrass(user_id int, amt int) (string, int) {
	_, err := db.ExecContext(dbctx, "insert into inventory_item(user_id,resource_id,quantity) values(?,1,?)"+
		" on duplicate key update quantity = quantity + ?", user_id, amt, amt)
	if err != nil {
		panic(err)
	}
	quantity := getResourceQuantity(user_id, GRASS)
	return "Bought: " + fmt.Sprint(amt), quantity
}

func sellGrass(user_id int, amt int) (string, int) {
	quantity := getResourceQuantity(user_id, GRASS)
	if amt > quantity {
		return "Failed to sell", quantity
	}
	_, err := db.ExecContext(dbctx, "update inventory_item set quantity = quantity - ? where user_id = ? and resource_id = 1", amt, user_id)
	if err != nil {
		panic(err)
	}
	return "Sold: " + fmt.Sprint(amt), quantity - amt
}

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

func buySellOperator(r *http.Request, user_id int, bsGrass func(int, int) (string, int)) (string, int) {
	var message string
	var quantity int
	q, err := strconv.Atoi(r.FormValue("quantityOfGrass"))
	if q < 0 {
		err = fmt.Errorf("negative quantity")
	}
	if err == nil {
		message, quantity = bsGrass(user_id, q)
	} else {
		message = "Invalid quantity"
		quantity = getResourceQuantity(user_id, GRASS)
	}
	return message, quantity
}

func handleTrack(w http.ResponseWriter, r *http.Request) {
	session := GetSession(r)
	usr, err := GetLoggedInUser(w, r, session)
	if err != nil {
		fmt.Printf("getLoggedInUser returned an error %s", err)
		return
	}
	// if r.URL.Query().Get("action") == "buy_grass" {
	// 	message, quantity = buySellOperator(r, user_id, buyGrass)
	// } else if r.URL.Query().Get("action") == "sell_grass" {
	// 	message, quantity = buySellOperator(r, user_id, sellGrass)
	// } else {
	// 	quantity = getResourceQuantity(user_id, GRASS)
	// }
	if r.URL.Query().Get("action") == "save" {
		var exLog common.ExerciseLog
		exLog.ExerciseId, _ = strconv.Atoi(r.FormValue("exercise_id"))
		exLog.Date = time.Now()
		exLog.Weight, _ = strconv.ParseFloat(r.FormValue("weight"), 64)
		exLog.Reps, _ = strconv.Atoi(r.FormValue("reps"))
		exLog.Sets, _ = strconv.Atoi(r.FormValue("sets"))
		_, err := db.ExecContext(dbctx, "insert into exercise_log(user_id,exercise_id,date,weight,reps,sets) values(?,?,?,?,?,?)", usr.Id, exLog.ExerciseId, exLog.Date, exLog.Weight, exLog.Reps, exLog.Sets)
		if err != nil {
			panic(err)
		}
		http.Redirect(w, r, "/seb/gymlog/track", http.StatusFound)
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
		exercises = append(exercises, ex)
	}
	return exercises, err
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	session := GetSession(r)
	usr, err := GetLoggedInUser(w, r, session)
	if err != nil {
		return
	}

	component := templates.Home(usr)
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
			panic(err)
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

	db, err = sql.Open("mysql", "gymlog:REDACTED@tcp(127.0.0.1:3306)/gymlog")
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

	fmt.Printf("Listening on %s\n", serverUrl)
	err = http.ListenAndServe(serverUrl, nil)
	if errors.Is(err, http.ErrServerClosed) {
		fmt.Printf("server closed\n")
	} else if err != nil {
		fmt.Printf("error starting server: %s\n", err)
		os.Exit(1)
	}
}
