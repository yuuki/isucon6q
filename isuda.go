package main

import (
	"bufio"
	"context"
	"crypto/sha1"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"html/template"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Songmu/strrand"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/unrolled/render"
	"github.com/patrickmn/go-cache"
)

const (
	sessionName   = "isuda_session"
	sessionSecret = "tonymoris"
)

var (
	isutarEndpoint string
	isupamEndpoint string

	baseUrl *url.URL
	db      *sql.DB
	sdb      *sql.DB
	re      *render.Render
	store   *sessions.CookieStore

	errInvalidUser = errors.New("Invalid User")

        ca = cache.New(5*time.Minute, 30*time.Second)
)

func setName(w http.ResponseWriter, r *http.Request) error {
	session := getSession(w, r)
	userID, ok := session.Values["user_id"]
	if !ok {
		return nil
	}
	setContext(r, "user_id", userID)
	u, ok := ca.Get(fmt.Sprintf("user:%d", userID))
	if !ok {
		return errInvalidUser
	}
	setContext(r, "user_name", u.(*User).Name)
	return nil
}

func authenticate(w http.ResponseWriter, r *http.Request) error {
	if u := getContext(r, "user_id"); u != nil {
		return nil
	}
	return errInvalidUser
}

func initializeHandler(w http.ResponseWriter, r *http.Request) {
	_, err := db.Exec(`DELETE FROM entry WHERE id > 7101`)
	panicIf(err)

	_, err = sdb.Exec("TRUNCATE star")
	panicIf(err)

	// loadspam
	{
		f, err := os.Open("/home/isucon/spam.txt")
		panicIf(err)
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			ca.Set(fmt.Sprintf("spam:%s", scanner.Text()), "novalid", cache.NoExpiration)
		}
	}
	{
		f, err := os.Open("/home/isucon/nospam.txt")
		panicIf(err)
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			ca.Set(fmt.Sprintf("spam:%s", scanner.Text()), "valid", cache.NoExpiration)
		}
	}

	var totalEntries int
	row := db.QueryRow(`SELECT COUNT(*) FROM entry`)
	err = row.Scan(&totalEntries)
	if err != nil && err != sql.ErrNoRows {
		panicIf(err)
	}
	ca.Set("count", totalEntries, cache.NoExpiration)

	rows, err := db.Query(`SELECT id,name,salt,password FROM user`)
	if err != nil && err != sql.ErrNoRows {
		panicIf(err)
	}
	for rows.Next() {
		u := User{}
		err := rows.Scan(&u.ID, &u.Name, &u.Salt, &u.Password)
		panicIf(err)
		ca.Set(fmt.Sprintf("user:%d", u.ID), &u, cache.NoExpiration)
		ca.Set(fmt.Sprintf("username:%s", u.Name), &u, cache.NoExpiration)
	}

	re.JSON(w, http.StatusOK, map[string]string{"result": "ok"})
}

func topHandler(w http.ResponseWriter, r *http.Request) {
	s1 := time.Now()
	if err := setName(w, r); err != nil {
		forbidden(w)
		return
	}

	perPage := 10
	p := r.URL.Query().Get("page")
	if p == "" {
		p = "1"
	}
	page, _ := strconv.Atoi(p)

	s2 := time.Now()

	rows, err := db.Query(fmt.Sprintf(
		"SELECT * FROM entry ORDER BY updated_at DESC LIMIT %d OFFSET %d",
		perPage, perPage*(page-1),
	))
	if err != nil && err != sql.ErrNoRows {
		panicIf(err)
	}
	entries := make([]*Entry, 0, 10)
	descriptions := make([]string, 0, 10)
	for rows.Next() {
		e := Entry{}
		err := rows.Scan(&e.ID, &e.AuthorID, &e.Keyword, &e.Description, &e.UpdatedAt, &e.CreatedAt, &e.KeywordLen)
		panicIf(err)
		//e.Html = htmlify(w, r, e.Description)
		e.Stars = loadStars(e.Keyword)
		descriptions = append(descriptions, e.Description)
		entries = append(entries, &e)
	}
	rows.Close()

	e2 := time.Now()
	log.Println(fmt.Sprintf("pager: %d msec", e2.Sub(s2).Nanoseconds() / 1000 / 1000))

	for i, description := range htmlify2(w, r, descriptions) {
		entries[i].Html = description
	}

	totalEntries, _ := ca.Get("count")

	lastPage := int(math.Ceil(float64(totalEntries.(int)) / float64(perPage)))
	pages := make([]int, 0, 10)
	start := int(math.Max(float64(1), float64(page-5)))
	end := int(math.Min(float64(lastPage), float64(page+5)))
	for i := start; i <= end; i++ {
		pages = append(pages, i)
	}

	re.HTML(w, http.StatusOK, "index", struct {
		Context  context.Context
		Entries  []*Entry
		Page     int
		LastPage int
		Pages    []int
	}{
		r.Context(), entries, page, lastPage, pages,
	})
	e1 := time.Now()
	log.Println(fmt.Sprintf("topHandler: %d msec", e1.Sub(s1).Nanoseconds() / 1000 / 1000))
}

func robotsHandler(w http.ResponseWriter, r *http.Request) {
	notFound(w)
}

func keywordPostHandler(w http.ResponseWriter, r *http.Request) {
	s1 := time.Now()

	if err := setName(w, r); err != nil {
		forbidden(w)
		return
	}
	if err := authenticate(w, r); err != nil {
		forbidden(w)
		return
	}

	keyword := r.FormValue("keyword")
	if keyword == "" {
		badRequest(w)
		return
	}
	userID := getContext(r, "user_id").(int)
	description := r.FormValue("description")

	s2 := time.Now()

	if isSpamContents(description) || isSpamContents(keyword) {
		http.Error(w, "SPAM!", http.StatusBadRequest)
		return
	}

	e2 := time.Now()
	log.Println(fmt.Sprintf("isSpamContents: %d msec", e2.Sub(s2).Nanoseconds() / 1000 / 1000))

	count, _ := ca.Get("count")
	ca.Set("count", count.(int)+1, cache.NoExpiration)

	_, err := db.Exec(`
		INSERT INTO entry (author_id, keyword, description, created_at, updated_at, keyword_length)
		VALUES (?, ?, ?, NOW(), NOW(), CHARACTER_LENGTH(keyword))
		ON DUPLICATE KEY UPDATE
		author_id = ?, keyword = ?, description = ?, updated_at = NOW(), keyword_length = CHARACTER_LENGTH(keyword)
	`, userID, keyword, description, userID, keyword, description)
	panicIf(err)
	http.Redirect(w, r, "/", http.StatusFound)

	e1 := time.Now()
	log.Println(fmt.Sprintf("keywordPostHandler: %d msec", e1.Sub(s1).Nanoseconds() / 1000 / 1000))
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if err := setName(w, r); err != nil {
		forbidden(w)
		return
	}

	re.HTML(w, http.StatusOK, "authenticate", struct {
		Context context.Context
		Action  string
	}{
		r.Context(), "login",
	})
}

func loginPostHandler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")

	u, ok := ca.Get(fmt.Sprintf("username:%s", name))
	if !ok {
		forbidden(w)
		return
	}
	user := u.(*User)
	if user.Password != fmt.Sprintf("%x", sha1.Sum([]byte(user.Salt+r.FormValue("password")))) {
		forbidden(w)
		return
	}
	session := getSession(w, r)
	session.Values["user_id"] = user.ID
	session.Save(r, w)
	http.Redirect(w, r, "/", http.StatusFound)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session := getSession(w, r)
	session.Options = &sessions.Options{MaxAge: -1}
	session.Save(r, w)
	http.Redirect(w, r, "/", http.StatusFound)
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if err := setName(w, r); err != nil {
		forbidden(w)
		return
	}

	re.HTML(w, http.StatusOK, "authenticate", struct {
		Context context.Context
		Action  string
	}{
		r.Context(), "register",
	})
}

func registerPostHandler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	pw := r.FormValue("password")
	if name == "" || pw == "" {
		badRequest(w)
		return
	}
	userID := register(name, pw)
	session := getSession(w, r)
	session.Values["user_id"] = userID
	session.Save(r, w)
	http.Redirect(w, r, "/", http.StatusFound)
}

func register(user string, pass string) int64 {
	salt, err := strrand.RandomString(`....................`)
	panicIf(err)
	res, err := db.Exec(`INSERT INTO user (name, salt, password, created_at) VALUES (?, ?, ?, NOW())`,
		user, salt, fmt.Sprintf("%x", sha1.Sum([]byte(salt+pass))))
	panicIf(err)
	lastInsertID, _ := res.LastInsertId()
	return lastInsertID
}

func keywordByKeywordHandler(w http.ResponseWriter, r *http.Request) {
	s1 := time.Now()

	if err := setName(w, r); err != nil {
		forbidden(w)
		return
	}

	keyword := mux.Vars(r)["keyword"]
	row := db.QueryRow(`SELECT * FROM entry WHERE keyword = ?`, keyword)
	e := Entry{}
	err := row.Scan(&e.ID, &e.AuthorID, &e.Keyword, &e.Description, &e.UpdatedAt, &e.CreatedAt, &e.KeywordLen)
	if err == sql.ErrNoRows {
		notFound(w)
		return
	}
	e.Html = htmlify(w, r, e.Description)
	e.Stars = loadStars(e.Keyword)

	re.HTML(w, http.StatusOK, "keyword", struct {
		Context context.Context
		Entry   Entry
	}{
		r.Context(), e,
	})

	e1 := time.Now()
	log.Println(fmt.Sprintf("keywordByKeywordHandler: %d msec", e1.Sub(s1).Nanoseconds() / 1000 / 1000))
}

func keywordByKeywordDeleteHandler(w http.ResponseWriter, r *http.Request) {
	s1 := time.Now()

	if err := setName(w, r); err != nil {
		forbidden(w)
		return
	}
	if err := authenticate(w, r); err != nil {
		forbidden(w)
		return
	}

	keyword := mux.Vars(r)["keyword"]
	if keyword == "" {
		badRequest(w)
		return
	}
	if r.FormValue("delete") == "" {
		badRequest(w)
		return
	}
	row := db.QueryRow(`SELECT * FROM entry WHERE keyword = ?`, keyword)
	e := Entry{}
	err := row.Scan(&e.ID, &e.AuthorID, &e.Keyword, &e.Description, &e.UpdatedAt, &e.CreatedAt, &e.KeywordLen)
	if err == sql.ErrNoRows {
		notFound(w)
		return
	}
	_, err = db.Exec(`DELETE FROM entry WHERE keyword = ?`, keyword)
	panicIf(err)
	http.Redirect(w, r, "/", http.StatusFound)

	e1 := time.Now()
	log.Println(fmt.Sprintf("keywordByDeleteHandler: %d msec", e1.Sub(s1).Nanoseconds() / 1000 / 1000))
}

func htmlify2(w http.ResponseWriter, r *http.Request, contents []string) []string {
	s1 := time.Now()
	rows, err := db.Query(`
		SELECT keyword FROM entry ORDER BY keyword_length DESC
	`)
	panicIf(err)
	entries := make([]*Entry, 0, 500)
	for rows.Next() {
		e := Entry{}
		err := rows.Scan(&e.Keyword)
		panicIf(err)
		entries = append(entries, &e)
	}
	rows.Close()
	e1 := time.Now()
	log.Println(fmt.Sprintf("selectkeyword: %d msec", e1.Sub(s1).Nanoseconds() / 1000 / 1000))

	s2 := time.Now()
	kw2sha := make(map[string]string)
	for _, entry := range entries {
		kw := entry.Keyword
		salt, ok := ca.Get(fmt.Sprintf("salt:%s", kw))
		if !ok {
			log.Println("salt:", kw)
			salt, _ = strrand.RandomString(`[a-zA-Z][あ-を][ア-ヲ]{20}`)
			ca.Set(fmt.Sprintf("salt:%s", kw), salt, cache.NoExpiration)
		}
		for i, content := range contents {
			contents[i] = strings.Replace(content, kw, salt.(string), -1)
		}
		kw2sha[kw] = salt.(string)
	}
	e2 := time.Now()
	log.Println(fmt.Sprintf("randomstring: %d msec", e2.Sub(s2).Nanoseconds() / 1000 / 1000))

	s3 := time.Now()
	for i, content := range contents {
		content = html.EscapeString(content)
		for kw, hash := range kw2sha {
			u, err := r.URL.Parse(baseUrl.String()+"/keyword/" + pathURIEscape(kw))
			panicIf(err)
			link := fmt.Sprintf("<a href=\"%s\">%s</a>", u, html.EscapeString(kw))
			content = strings.Replace(content, hash, link, -1)
		}
		contents[i] = content
		//contents[i] = strings.Replace(content, "\n", "<br />\n", -1)
	}

	e3 := time.Now()
	log.Println(fmt.Sprintf("replacehash: %d msec", e3.Sub(s3).Nanoseconds() / 1000 / 1000))

	return contents
}

func htmlify(w http.ResponseWriter, r *http.Request, content string) string {
	if content == "" {
		return ""
	}
	s1 := time.Now()
	rows, err := db.Query(`
		SELECT keyword FROM entry ORDER BY CHARACTER_LENGTH(keyword) DESC
	`)
	panicIf(err)
	entries := make([]*Entry, 0, 500)
	for rows.Next() {
		e := Entry{}
		err := rows.Scan(&e.Keyword)
		panicIf(err)
		entries = append(entries, &e)
	}
	rows.Close()
	e1 := time.Now()
	log.Println(fmt.Sprintf("selectkeyword: %d msec", e1.Sub(s1).Nanoseconds() / 1000 / 1000))

	s2 := time.Now()
	kw2sha := make(map[string]string)
	for _, entry := range entries {
		kw := entry.Keyword
		salt, ok := ca.Get(fmt.Sprintf("salt:%s", kw))
		if !ok {
			salt, _ = strrand.RandomString(`[a-zA-Z][あ-を][ア-ヲ]{20}`)
			ca.Set(fmt.Sprintf("salt:%s", kw), salt, cache.NoExpiration)
		}
		content = strings.Replace(content, kw, salt.(string), -1)
		kw2sha[kw] = salt.(string)
	}
	e2 := time.Now()
	log.Println(fmt.Sprintf("randomstring: %d msec", e2.Sub(s2).Nanoseconds() / 1000 / 1000))

	content = html.EscapeString(content)
	for kw, hash := range kw2sha {
		u, err := r.URL.Parse(baseUrl.String()+"/keyword/" + pathURIEscape(kw))
		panicIf(err)
		link := fmt.Sprintf("<a href=\"%s\">%s</a>", u, html.EscapeString(kw))
		content = strings.Replace(content, hash, link, -1)
	}
	return content
}

func loadStars(keyword string) []*Star {
	rows, err := sdb.Query(`SELECT * FROM star WHERE keyword = ?`, keyword)
	if err != nil && err != sql.ErrNoRows {
		panicIf(err)
		return nil
	}

	stars := make([]*Star, 0, 10)
	for rows.Next() {
		s := &Star{}
		err := rows.Scan(&s.ID, &s.Keyword, &s.UserName, &s.CreatedAt)
		panicIf(err)
		stars = append(stars, s)
	}
	rows.Close()

	return stars
}

func isSpamContents(content string) bool {
	hash := fmt.Sprintf("%x", sha1.Sum([]byte(content)))
	res, ok := ca.Get("spam:"+hash)
	if ok {
		if res == "valid" {
			return false
		} else if res == "novalid" {
			return true
		}
	}

	v := url.Values{}
	v.Set("content", content)
	resp, err := http.PostForm(isupamEndpoint, v)
	panicIf(err)
	defer resp.Body.Close()

	var data struct {
		Valid bool `json:valid`
	}
	err = json.NewDecoder(resp.Body).Decode(&data)
	panicIf(err)

	if data.Valid {
		f, err := os.OpenFile("/home/isucon/nospam.txt", os.O_WRONLY | os.O_CREATE | os.O_APPEND, 0644)
		panicIf(err)
		f.WriteString(hash+"\n")
		log.Println("nospam: ", hash)
	} else {
		f, err := os.OpenFile("/home/isucon/spam.txt", os.O_WRONLY | os.O_CREATE | os.O_APPEND, 0644)
		panicIf(err)
		f.WriteString(hash+"\n")
		log.Println("spam: ", hash)
	}

	return !data.Valid
}

func getContext(r *http.Request, key interface{}) interface{} {
	return r.Context().Value(key)
}

func setContext(r *http.Request, key, val interface{}) {
	if val == nil {
		return
	}

	r2 := r.WithContext(context.WithValue(r.Context(), key, val))
	*r = *r2
}

func getSession(w http.ResponseWriter, r *http.Request) *sessions.Session {
	session, _ := store.Get(r, sessionName)
	return session
}

func starsHandler(w http.ResponseWriter, r *http.Request) {
	keyword := r.FormValue("keyword")
	rows, err := db.Query(`SELECT * FROM star WHERE keyword = ?`, keyword)
	if err != nil && err != sql.ErrNoRows {
		panicIf(err)
		return
	}

	stars := make([]*Star, 0, 10)
	for rows.Next() {
		s := &Star{}
		err := rows.Scan(&s.ID, &s.Keyword, &s.UserName, &s.CreatedAt)
		panicIf(err)
		stars = append(stars, s)
	}
	rows.Close()

	re.JSON(w, http.StatusOK, map[string][]*Star{
		"result": stars,
	})
}

func starsPostHandler(w http.ResponseWriter, r *http.Request) {
	keyword := r.FormValue("keyword")

	row := db.QueryRow(`SELECT * FROM entry WHERE keyword = ?`, keyword)
	e := Entry{}
	err := row.Scan(&e.ID, &e.AuthorID, &e.Keyword, &e.Description, &e.UpdatedAt, &e.CreatedAt)
	if err == sql.ErrNoRows {
		notFound(w)
		return
	}

	user := r.FormValue("user")
	_, err = sdb.Exec(`INSERT INTO star (keyword, user_name, created_at) VALUES (?, ?, NOW())`, keyword, user)
	panicIf(err)

	re.JSON(w, http.StatusOK, map[string]string{"result": "ok"})
}

func main() {
	host := os.Getenv("ISUDA_DB_HOST")
	if host == "" {
		host = "localhost"
	}
	portstr := os.Getenv("ISUDA_DB_PORT")
	if portstr == "" {
		portstr = "3306"
	}
	port, err := strconv.Atoi(portstr)
	if err != nil {
		log.Fatalf("Failed to read DB port number from an environment variable ISUDA_DB_PORT.\nError: %s", err.Error())
	}
	user := os.Getenv("ISUDA_DB_USER")
	if user == "" {
		user = "root"
	}
	password := os.Getenv("ISUDA_DB_PASSWORD")
	dbname := os.Getenv("ISUDA_DB_NAME")
	if dbname == "" {
		dbname = "isuda"
	}

	db, err = sql.Open("mysql", fmt.Sprintf(
		"%s:%s@tcp(%s:%d)/%s?loc=Local&parseTime=true",
		user, password, host, port, dbname,
	))
	if err != nil {
		log.Fatalf("Failed to connect to DB: %s.", err.Error())
	}
	db.Exec("SET SESSION sql_mode='TRADITIONAL,NO_AUTO_VALUE_ON_ZERO,ONLY_FULL_GROUP_BY'")
	db.Exec("SET NAMES utf8mb4")

	sdb, err = sql.Open("mysql", fmt.Sprintf(
		"%s:%s@tcp(%s:%d)/%s?loc=Local&parseTime=true",
		user, password, host, port, "isutar",
	))
	if err != nil {
		log.Fatalf("Failed to connect to DB: %s.", err.Error())
	}
	db.Exec("SET SESSION sql_mode='TRADITIONAL,NO_AUTO_VALUE_ON_ZERO,ONLY_FULL_GROUP_BY'")
	db.Exec("SET NAMES utf8mb4")

	isutarEndpoint = os.Getenv("ISUTAR_ORIGIN")
	if isutarEndpoint == "" {
		isutarEndpoint = "http://localhost:5001"
	}
	isupamEndpoint = os.Getenv("ISUPAM_ORIGIN")
	if isupamEndpoint == "" {
		isupamEndpoint = "http://localhost:5050"
	}

	store = sessions.NewCookieStore([]byte(sessionSecret))

	re = render.New(render.Options{
		Directory: "views",
		Funcs: []template.FuncMap{
			{
				"url_for": func(path string) string {
					return baseUrl.String() + path
				},
				"title": func(s string) string {
					return strings.Title(s)
				},
				"raw": func(text string) template.HTML {
					return template.HTML(text)
				},
				"add": func(a, b int) int { return a + b },
				"sub": func(a, b int) int { return a - b },
				"entry_with_ctx": func(entry Entry, ctx context.Context) *EntryWithCtx {
					return &EntryWithCtx{Context: ctx, Entry: entry}
				},
			},
		},
	})

	r := mux.NewRouter()
	r.HandleFunc("/", myHandler(topHandler))
	r.HandleFunc("/initialize", myHandler(initializeHandler)).Methods("GET")
	r.HandleFunc("/robots.txt", myHandler(robotsHandler))
	r.HandleFunc("/keyword", myHandler(keywordPostHandler)).Methods("POST")

	l := r.PathPrefix("/login").Subrouter()
	l.Methods("GET").HandlerFunc(myHandler(loginHandler))
	l.Methods("POST").HandlerFunc(myHandler(loginPostHandler))
	r.HandleFunc("/logout", myHandler(logoutHandler))

	g := r.PathPrefix("/register").Subrouter()
	g.Methods("GET").HandlerFunc(myHandler(registerHandler))
	g.Methods("POST").HandlerFunc(myHandler(registerPostHandler))

	k := r.PathPrefix("/keyword/{keyword}").Subrouter()
	k.Methods("GET").HandlerFunc(myHandler(keywordByKeywordHandler))
	k.Methods("POST").HandlerFunc(myHandler(keywordByKeywordDeleteHandler))

	s := r.PathPrefix("/stars").Subrouter()
	s.Methods("GET").HandlerFunc(myHandler(starsHandler))
	s.Methods("POST").HandlerFunc(myHandler(starsPostHandler))

	r.PathPrefix("/").Handler(http.FileServer(http.Dir("./public/")))
	log.Fatal(http.ListenAndServe(":5000", r))
}
