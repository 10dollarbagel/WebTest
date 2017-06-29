package main

import (
	"html/template"
	"io"
	"log"
	"net/http"
	"fmt"
	"github.com/satori/uuid"
	"golang.org/x/crypto/bcrypt"
)


type user struct{
	username string
	password []byte
}
var tpl *template.Template
var usersDB = make(map[string]user)
var sessDB = make(map[string]string)

func init(){
	bs, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.MinCost)
	usersDB["test"]=user{"test",bs}
}
/*type Cookie struct {
//	Name  string
	Value string

	Path       string    // optional
	Domain     string    // optional
	Expires    time.Time // optional
	RawExpires string    // for reading cookies only

	// MaxAge=0 means no 'Max-Age' attribute specified.
	// MaxAge<0 means delete cookie now, equivalently 'Max-Age: 0'
	// MaxAge>0 means Max-Age attribute present and given in seconds
	MaxAge   int
	Secure   bool
	HttpOnly bool
	Raw      string
	Unparsed []string // Raw text of unparsed attribute-value pairs
}*/
var cookie http.Cookie
func init() {
	tpl = template.Must(template.ParseGlob("templates/*.html"))
}

func main() {

	http.Handle("/static/", http.StripPrefix("/static", http.FileServer(http.Dir("static"))))
	http.HandleFunc("/", index)
	http.HandleFunc("/cat", cat)
	http.HandleFunc("/secondPage.html", second)
	http.HandleFunc("/signup.html", signup)
	http.HandleFunc("/login", login)
	http.HandleFunc("/signup", signup)
	log.Fatal(http.ListenAndServe(":8080", nil))

}

func cat(w http.ResponseWriter, r *http.Request) {

	tpl.ExecuteTemplate(w, "cat.html", nil)
}
func index(w http.ResponseWriter, r *http.Request) {

	tpl.ExecuteTemplate(w, "index.html", nil)
}
func second(w http.ResponseWriter, r *http.Request) {

	tpl.ExecuteTemplate(w, "secondPage.html", nil)
}

func login(w http.ResponseWriter, r *http.Request) {

	if alreadyLoggedin(r){
		http.Redirect(w, r, "/", http.StatusSeeOther)

	}
	if r.Method==http.MethodPost {
		name := r.FormValue("name")
		pass := r.FormValue("password")
		//check username
		u, ok := usersDB[name]
		if !ok {
			io.WriteString(w, "username and password dont match")
			return
		}
		//check password
		err := bcrypt.CompareHashAndPassword(u.password, []byte(pass))
		if err != nil {
			io.WriteString(w, "username and password dont match")
			return
		}

		//create session
		sID := uuid.NewV4()
		c := &http.Cookie{Name: "session", Value: sID.String()}
		http.SetCookie(w, c)
		sessDB[c.Value] = name
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	tpl.ExecuteTemplate(w, "login.html", nil)

}


func signup(w http.ResponseWriter, r *http.Request) {

	if alreadyLoggedin(r){
		http.Redirect(w, r, "/", http.StatusSeeOther)
		fmt.Println("got here")
		io.WriteString(w, "Already logged in")
	}


	name:= r.FormValue("name")
	pass:= r.FormValue("password")

	var b bool
	bs,err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.MinCost)
	if err != nil{
		http.Error(w,"Internal Server Error", http.StatusInternalServerError)
	}
	u := user{name, bs}

	sID:= uuid.NewV4()
	c:=&http.Cookie{
		Name:"session",
		Value: sID.String(),
	}
	http.SetCookie(w, c)

	tpl.ExecuteTemplate(w,"signup.html", nil)

		if name!="" && pass!= "" {
		for key, _ := range usersDB {
			if key == name {
				b = true

			}

		}
		if b == false {

			usersDB[name] = u
			io.WriteString(w, "Registration Successful for "+name)

		} else {
			io.WriteString(w, "Username already taken")
		}
	}

	}


func alreadyLoggedin(r *http.Request) bool {
	c, err:=r.Cookie("session")
	if err !=nil{
		return false
	}
	fmt.Println("got")
	un:= sessDB[c.Value]
	_, ok := usersDB[un]
	return ok
}