package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/gin-contrib/static"
	"github.com/gin-gonic/gin"
	"github.com/olahol/melody"
	uuid "github.com/satori/go.uuid"
	mailgun "gopkg.in/mailgun/mailgun-go.v1"
)

const (
	dataDirectory string = "./data/"
)

type rjFileSystem struct {
	http.FileSystem
	root    string
	indexes bool
}

// RJGlobal is for storing global information about projects and the project root URL, committed
type RJGlobal struct {
	Projects []RJProject `json:"projects"`
	URL      string      `json:"url"`
}

// RJProject is for storing global information about a given project, committed
type RJProject struct {
	Description string `json:"description"`
	ID          string `json:"id"`
	Name        string `json:"name"`
	SitePath    string `json:"sitePath"`
	URL         string `json:"url"`
}

type rjPhoneManager struct {
	Conversations map[string][]Message `json:"conversations"`
}

func getUUID() string {
	var err error
	var uid uuid.UUID

	for uid, err = uuid.NewV4(); err != nil; {
		uid, err = uuid.NewV4()
	}

	return uid.String()
}

func getPhoneData(pathToData string) (*rjPhoneManager, error) {
	if _, err := os.Stat(pathToData); err != nil {
		return nil, err
	}

	phoneData, err := os.Open(pathToData)

	defer phoneData.Close()

	if err != nil {
		return nil, err
	}

	var rjPhone rjPhoneManager

	if err := json.NewDecoder(phoneData).Decode(&rjPhone); err != nil {
		return nil, err
	}

	return &rjPhone, nil
}

func (rjPhone *rjPhoneManager) writePhoneData(pathToData string) error {
	phoneData, err := os.OpenFile(pathToData, os.O_CREATE|os.O_WRONLY, 0644)

	defer phoneData.Close()

	if err != nil {
		return err
	}

	if err := json.NewEncoder(phoneData).Encode(rjPhone); err != nil {
		return err
	}

	return nil
}

func (rjPhone *rjPhoneManager) addToPhoneConversation(phoneNumber string, msg string, isRecieved bool) Message {
	_, exists := rjPhone.Conversations[phoneNumber]

	if !exists {
		rjPhone.Conversations[phoneNumber] = make([]Message, 0)
	}

	conversation := rjPhone.Conversations[phoneNumber]

	message := Message{IsRecieved: isRecieved, Message: msg, TimeRecieved: time.Now()}

	conversation = append(conversation, message)

	rjPhone.Conversations[phoneNumber] = conversation

	return message
}

type Message struct {
	IsRecieved   bool      `json:"isRecieved"`
	Message      string    `json:"message"`
	TimeRecieved time.Time `json:"timeRecieved"`
}

type WSMessage struct {
	IsRecieved   bool      `json:"isRecieved"`
	Message      string    `json:"message"`
	OtherNumber  string    `json:"otherNumber"`
	TimeRecieved time.Time `json:"timeRecieved"`
}

func (m Message) Send(to string) error {
	msgData := url.Values{}

	msgData.Set("To", to)
	msgData.Set("From", information.Number)
	msgData.Set("Body", m.Message)

	msgDataReader := *strings.NewReader(msgData.Encode())

	client := &http.Client{Timeout: 3 * time.Second}

	req, err := http.NewRequest("POST", fmt.Sprintf("https://api.twilio.com/2010-04-01/Accounts/%s/Messages.json", information.Sid), &msgDataReader)

	if err != nil {
		return err
	}

	req.SetBasicAuth(information.Sid, information.Token)

	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	_, err = client.Do(req)

	return err
}

func (l *rjFileSystem) Exists(prefix string, filepath string) bool {
	if p := strings.TrimPrefix(filepath, prefix); len(p) < len(filepath) {
		name := path.Join(l.root, p)
		_, err := os.Stat(name)
		if err != nil {
			return false
		}

		return true
	}
	return false
}

func NewRjFileSystem(root string) *rjFileSystem {
	return &rjFileSystem{
		FileSystem: gin.Dir(root, true),
		root:       root,
		indexes:    true,
	}
}

// RjServe returns a middleware handler that serves static files in the given directory.
func RjServe(urlPrefix string, fs static.ServeFileSystem) gin.HandlerFunc {
	fileserver := http.FileServer(fs)

	if urlPrefix != "" {
		fileserver = http.StripPrefix(urlPrefix, fileserver)
	}

	return func(c *gin.Context) {
		if fs.Exists(urlPrefix, c.Request.URL.Path) {

			if strings.HasSuffix(c.Request.URL.Path, "rjResume.pdf") {
				addr := getIPAdress(c.Request)

				mux.Lock()
				seen := resumeRequesters[addr]
				resumeRequesters[addr]++
				mux.Unlock()

				myEmail := mEmail
				lmg := mg
				if seen == 0 {
					_, _, err := lmg.Send(mailgun.NewMessage("robot@mail.therileyjohnson.com", fmt.Sprintf("Someone at %s Downloaded Your Resume", addr), "See the title dummy", myEmail))
					if err != nil {
						fmt.Println("Error sending email to yourself")
					}
				}
			}

			fileserver.ServeHTTP(c.Writer, c.Request)
			c.Abort()
		}
	}
}

// RjServe returns a middleware handler that serves static files in the given directory.
func RjGeneralFileServer(urlPrefix string, fs static.ServeFileSystem) gin.HandlerFunc {
	fileserver := http.FileServer(fs)

	if urlPrefix != "" {
		fileserver = http.StripPrefix(urlPrefix, fileserver)
	}

	return func(c *gin.Context) {
		if fs.Exists(urlPrefix, c.Request.URL.Path) {
			fileserver.ServeHTTP(c.Writer, c.Request)
			c.Abort()
		}
	}
}

func getInfo() (info, error) {
	var information info
	fi, err := os.Open(path.Join(dataDirectory, "keys.json"))

	if err != nil {
		return info{}, err
	}

	err = json.NewDecoder(fi).Decode(&information)

	return information, err
}

//Function for determining which snapcode will show on the template
func getSnap() string {
	if rand.Intn(2) == 1 {
		return "snapcode_cash"
	}
	return "snapcode_casher"
}

//This, isPrivateSubnet, getIPAdress, and ipRange are from: https://husobee.github.io/golang/ip-address/2015/12/17/remote-ip-go.html
//inRange - check to see if a given ip address is within a range given
func inRange(r ipRange, ipAddress net.IP) bool {
	// strcmp type byte comparison
	if bytes.Compare(ipAddress, r.start) >= 0 && bytes.Compare(ipAddress, r.end) < 0 {
		return true
	}
	return false
}

// isPrivateSubnet - check to see if this ip is in a private subnet
func isPrivateSubnet(ipAddress net.IP) bool {
	// my use case is only concerned with ipv4 atm
	if ipCheck := ipAddress.To4(); ipCheck != nil {
		// iterate over all our ranges
		for _, r := range privateRanges {
			// check if this ip is in a private range
			if inRange(r, ipAddress) {
				return true
			}
		}
	}
	return false
}

func getIPAdress(r *http.Request) string {
	for _, h := range []string{"X-Forwarded-For", "X-Real-Ip"} {
		addresses := strings.Split(r.Header.Get(h), ",")
		// march from right to left until we get a public address
		// that will be the address right before our proxy.
		for i := len(addresses) - 1; i >= 0; i-- {
			ip := strings.TrimSpace(addresses[i])
			// header can contain spaces too, strip those out.
			realIP := net.ParseIP(ip)
			if !realIP.IsGlobalUnicast() || isPrivateSubnet(realIP) {
				// bad address, go to next
				continue
			}
			return ip
		}
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if aip := net.ParseIP(ip); aip != nil && err == nil {
		if aip.IsGlobalUnicast() && !isPrivateSubnet(aip) {
			return aip.String()
		}
	}
	return ""
}

func getRjGlobal(projectRootPath string) (RJGlobal, error) {
	var rjGlobal RJGlobal

	if _, err := os.Stat(path.Join(projectRootPath, "RJglobal.json")); err != nil {
		return RJGlobal{}, errors.New("could not find RJglobal file")
	}

	rjGlobalFile, err := os.Open(path.Join(projectRootPath, "RJglobal.json"))

	defer rjGlobalFile.Close()

	if err != nil {
		return RJGlobal{}, err
	}

	if err := json.NewDecoder(rjGlobalFile).Decode(&rjGlobal); err != nil {
		return RJGlobal{}, err
	}

	return rjGlobal, nil
}

func executeTemplate(w http.ResponseWriter, t string, d interface{}) {
	if err := tpl.ExecuteTemplate(w, t, d); err != nil {
		print(err)
	}
}

func writeStructToJSON(strct interface{}, path string) {
	res, err := json.Marshal(strct)
	if err != nil {
		println(err)
		return
	}
	err = ioutil.WriteFile(path, res, 0644)
}

func writeInfo(information info) error {
	informationBytes, err := json.Marshal(information)

	if err != nil {
		return err
	}

	return ioutil.WriteFile(path.Join(dataDirectory, "keys.json"), informationBytes, 0644)
}

func (vT *visiTracker) InSlice(a string) bool {
	for _, b := range vT.IPList {
		if b == a {
			return true
		}
	}
	return false
}

func chat(c *gin.Context) { executeTemplate(c.Writer, "chat.gohtml", vT) }

// func phoneCall(c *gin.Context) {
// 	bytes, err := httputil.DumpRequest(c.Request, true)

// 	if err != nil {
// 		bytes = []byte("FART")
// 	}

// 	ioutil.WriteFile("../httpCall.txt", bytes, 0644)

// 	c.Writer.Write([]byte("COOL"))
// }

func handleAuthenticate(c *gin.Context) {
	var loginInformation struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	defer c.Request.Body.Close()

	err := json.NewDecoder(c.Request.Body).Decode(&loginInformation)

	if err != nil {
		c.JSON(500, gin.H{
			"error": "could not decode payload",
		})
		return
	}

	if loginInformation.Username != information.PhoneUser || loginInformation.Password != information.PhonePass {
		fmt.Println(loginInformation, information.PhoneUser, information.PhonePass)
		c.JSON(500, gin.H{
			"error": "incorrect login information",
		})
		return
	}

	token := getUUID()

	httpSessions[token] = true

	c.SetCookie("token", token, 999, "", "https://therileyjohnson.com", true, false)

	c.JSON(200, gin.H{
		"token": token,
	})
}

func authenticatePhone(c *gin.Context) {
	var loginInformation struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	defer c.Request.Body.Close()

	err := json.NewDecoder(c.Request.Body).Decode(&loginInformation)

	if err != nil {
		c.JSON(400, gin.H{
			"error": "could not decode payload",
		})
		return
	}

	if loginInformation.Username != information.PhoneUser || loginInformation.Password != information.PhonePass {
		fmt.Println(loginInformation, information.PhoneUser, information.PhonePass)
		c.JSON(400, gin.H{
			"error": "incorrect login information",
		})
		return
	}

	token := getUUID()

	httpSessions[token] = true

	c.SetCookie("token", token, 999, "/phone", "https://therileyjohnson.com", true, false)

	c.JSON(200, gin.H{
		"token": token,
	})
}

func authenticatedPhoneGetRoute(function func(*gin.Context)) func(*gin.Context) {
	return func(c *gin.Context) {
		token := c.Param("token")

		fmt.Println(httpSessions[token])

		if httpSessions[token] {
			function(c)
		} else {
			c.JSON(400, gin.H{
				"error": "an error occured",
			})
		}

	}
}

func authenticatedPostRoute(function func(*gin.Context)) func(*gin.Context) {
	return func(c *gin.Context) {
		var token struct {
			Token string `json:"token"`
		}

		bodyBytes, err := ioutil.ReadAll(c.Request.Body)

		if err != nil {
			fmt.Println(err)

			c.JSON(400, gin.H{
				"error": "an error occured",
			})

			return
		}

		err = json.Unmarshal(bodyBytes, &token)

		if err != nil {
			fmt.Println(err)

			c.JSON(400, gin.H{
				"error": "an error occured",
			})

			return
		}

		c.Request.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))

		if httpSessions[token.Token] {
			function(c)
		} else {
			c.JSON(400, gin.H{
				"error": "an error occured",
			})
		}
	}
}

func authenticatedRoute(handlerFunction func(*gin.Context)) func(*gin.Context) {
	return func(c *gin.Context) {
		var token string

		switch {
		case c.Request.Header.Get("auth") != "":
			token = c.Request.Header.Get("auth")
		case c.Query("auth") != "":
			token = c.Query("auth")
		default:
			tokenCookie, err := c.Request.Cookie("token")

			if err == nil {
				token = tokenCookie.Value
			}
		}

		if token != "" && httpSessions[token] {
			handlerFunction(c)
		} else {
			c.JSON(500, gin.H{
				"error": true,
				"msg":   "invalid auth",
			})
		}
	}
}

func phoneSMS(phoneWSController *melody.Melody) func(*gin.Context) {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Content-Type", "text/html")

		c.Writer.Write([]byte("<Response></Response>"))

		phoneMux.Lock()
		defer phoneMux.Unlock()

		from := c.PostForm("From")
		body := c.PostForm("Body")

		message := rjWebPhone.addToPhoneConversation(from, body, true)

		err := rjWebPhone.writePhoneData(path.Join(dataDirectory, "phoneData.json"))

		if err != nil {
			fmt.Println(err)
		}

		messageBytes, err := json.Marshal(&WSMessage{message.IsRecieved, message.Message, from, message.TimeRecieved})

		if err != nil {
			fmt.Println(err)
		}

		phoneWSController.Broadcast(messageBytes)
	}
}

func getPhoneConversations(c *gin.Context) {
	json.NewEncoder(c.Writer).Encode(rjWebPhone.Conversations)
}

func makePhoneSMS(phoneWSController *melody.Melody) func(*gin.Context) {
	return func(c *gin.Context) {
		var phoneWSMessage struct {
			Number  string `json:"number"`
			Message string `json:"message"`
		}

		err := json.NewDecoder(c.Request.Body).Decode(&phoneWSMessage)

		if err != nil {
			c.JSON(400, gin.H{
				"error": "could not decode payload",
			})
			return
		}

		message := Message{IsRecieved: false, Message: phoneWSMessage.Message, TimeRecieved: time.Now()}

		err = message.Send(phoneWSMessage.Number)

		if err != nil {
			c.JSON(400, gin.H{
				"error": "could not send sms",
			})
			return
		}

		messageBytes, err := json.Marshal(&WSMessage{message.IsRecieved, message.Message, phoneWSMessage.Number, message.TimeRecieved})

		if err != nil {
			c.JSON(400, gin.H{
				"error": "could not marshall message json",
			})
			return
		}

		rjWebPhone.addToPhoneConversation(phoneWSMessage.Number, phoneWSMessage.Message, false)

		err = rjWebPhone.writePhoneData(path.Join(dataDirectory, "phoneData.json"))

		if err != nil {
			fmt.Println(err)
		}

		c.JSON(200, gin.H{
			"error": "",
		})

		phoneWSController.Broadcast(messageBytes)

		if err != nil {
			fmt.Println(err)
		}
	}
}

func naruto(c *gin.Context) {
	executeTemplate(c.Writer, "naruto.gohtml", vT)
}

func phone(c *gin.Context) {
	executeTemplate(c.Writer, "phone.gohtml", vT)
}

// func serveFile(c *gin.Context) {
// 	if strings.HasSuffix(c.Request.URL.Path, "rjResume.pdf") {
// 		addr := getIPAdress(c.Request)
// 		mux.Lock()
// 		seen := resumeRequesters[addr]
// 		resumeRequesters[addr]++
// 		myEmail := mEmail
// 		lmg := mg
// 		mux.Unlock()
// 		if seen == 0 {
// 			_, _, err := lmg.Send(mailgun.NewMessage("robot@mail.therileyjohnson.com", fmt.Sprintf("Someone at %s Downloaded Your Resume", addr), "See the title dummy", myEmail))
// 			if err != nil {
// 				fmt.Println("Error sending email to yourself")
// 			}
// 		}
// 	}
// 	file_serve := static.Serve("/public", static.LocalFile("static/", true))
// 	file_serve(c)
// 	// http.ServeFile(c.Writer, c.Request, "./static"+c.Request.URL.Path)
// }

func index(c *gin.Context) {
	if c.Request.URL.Query()["check"] == nil {
		mux.Lock()
		vT.V++
		if ip := getIPAdress(c.Request); ip != "" && !vT.InSlice(ip) {
			vT.Uv++
			vT.IPList = append(vT.IPList, ip)
		}
		mux.Unlock()
		go writeStructToJSON(vT, path.Join(dataDirectory, "numer.json"))
	}

	executeTemplate(c.Writer, "index.gohtml", vT)
}

func newTrimPrefixReverseProxy(target *url.URL, prefix string) *httputil.ReverseProxy {
	targetHasSlash := strings.HasSuffix(target.Path, "/")

	director := func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host

		req.URL.Path = strings.TrimPrefix(req.URL.Path, prefix)

		requestHasSlash := strings.HasPrefix(req.URL.Path, "/")

		switch {
		case targetHasSlash && requestHasSlash:
			req.URL.Path = target.Path + req.URL.Path[1:]
		case !targetHasSlash && !requestHasSlash:
			req.URL.Path = target.Path + "/" + req.URL.Path
		default:
			req.URL.Path = target.Path + req.URL.Path
		}
	}

	return &httputil.ReverseProxy{Director: director, FlushInterval: -1}
}

//ipRange - a structure that holds the start and end of a range of ip addresses
type ipRange struct {
	start net.IP
	end   net.IP
}

type visiTracker struct {
	V      int      `json:"numb"`
	Uv     int      `json:"uniq"`
	IPList []string `json:"ips"`
}

type ipUpdate struct {
	Error, IP string
}

//Struct to hold the private and public keys for the MailGun API
type info struct {
	Private    string `json:"private"`
	Public     string `json:"public"`
	KdsuIP     string `json:"kdsuIP"`
	MailServer string `json:"mailServer"`
	MyEmail    string `json:"myEmail"`
	Spyl       string `json:"spyLogin"`
	Spyp       string `json:"spyPass"`
	GPass      string `json:"gPass"`
	Sid        string `json:"sid"`
	Token      string `json:"token"`
	Number     string `json:"number"`
	LyricKey   string `json:"lyric_key"`
	Production bool   `json:"production"`
	ProPort    string `json:"pro-port"`
	PhoneUser  string `json:"phoneUser"`
	PhonePass  string `json:"phonePass"`
	DevPort    string `json:"dev-port"`
	CertPath   string `json:"certPath"`
	SecretPath string `json:"secretPath"`
}

var privateRanges = []ipRange{
	{
		start: net.ParseIP("10.0.0.0"),
		end:   net.ParseIP("10.255.255.255"),
	},
	{
		start: net.ParseIP("100.64.0.0"),
		end:   net.ParseIP("100.127.255.255"),
	},
	{
		start: net.ParseIP("172.16.0.0"),
		end:   net.ParseIP("172.31.255.255"),
	},
	{
		start: net.ParseIP("192.0.0.0"),
		end:   net.ParseIP("192.0.0.255"),
	},
	{
		start: net.ParseIP("192.168.0.0"),
		end:   net.ParseIP("192.168.255.255"),
	},
	{
		start: net.ParseIP("198.18.0.0"),
		end:   net.ParseIP("198.19.255.255"),
	},
}

var tpl *template.Template
var vT visiTracker
var httpSessions map[string]bool
var information info
var mux sync.Mutex
var phoneMux sync.Mutex
var mg mailgun.Mailgun
var certPath, mEmail, port, secretPath string
var resumeRequesters map[string]int
var rjWebPhone *rjPhoneManager

func init() {
	rand.Seed(time.Now().UTC().UnixNano())

	httpSessions = make(map[string]bool)
	resumeRequesters = make(map[string]int)

	fi, err := ioutil.ReadFile(path.Join(dataDirectory, "numer.json"))

	if err == nil {
		json.Unmarshal(fi, &vT)
	} else {
		vT = visiTracker{0, 0, []string{}}
	}

	tpl = template.Must(template.New("").Funcs(template.FuncMap{"snapCode": getSnap}).ParseGlob("templates/*.gohtml"))

	information, err = getInfo()

	mg = mailgun.NewMailgun(information.MailServer, information.Private, information.Public)
	mEmail = information.MyEmail

	certPath = information.CertPath
	secretPath = information.SecretPath

	if information.Production {
		port = information.ProPort
	} else {
		port = information.DevPort
	}

	rjWebPhone, err = getPhoneData(path.Join(dataDirectory, "phoneData.json"))

	if err != nil {
		rjWebPhone = &rjPhoneManager{Conversations: make(map[string][]Message)}
	}
}

func main() {
	// rjGlobal, err := getRjGlobal("./")

	// if err != nil {
	// 	log.Fatal(err)
	// }

	httpsRouter := gin.Default()
	httpRouter := gin.Default()

	chatWSController := melody.New()
	phoneWSController := melody.New()

	// Postponed until after https update
	// r.POST("/update/site", func(context *gin.Context) {
	// 	context.Writer.Write([]byte("updating..."))
	// 	os.Exit(9)
	// })
	// Postponed until after https update
	// r.POST("/update/rob", func(context *gin.Context) {
	// 	context.Writer.Write([]byte("updating..."))
	// 	os.Exit(9)
	// })

	chatWSConnectionHandler := func(c *gin.Context) {
		chatWSController.HandleRequest(c.Writer, c.Request)
	}

	chatWSController.HandleMessage(func(s *melody.Session, msg []byte) {
		chatWSController.Broadcast(msg)
	})

	phoneWSConnectionHandler := func(c *gin.Context) {
		phoneWSController.HandleRequest(c.Writer, c.Request)

		fmt.Println(phoneWSController.Broadcast([]byte("test")))
	}

	// phoneWSController.HandleMessage(func(s *melody.Session, msg []byte) {
	// 	var phoneWSMessage struct {
	// 		Number  string `json:"number"`
	// 		Message string `json:"message"`
	// 	}

	// 	err := json.Unmarshal(msg, &phoneWSMessage)

	// 	if err != nil {
	// 		fmt.Println(err)
	// 		return
	// 	}

	// 	phoneWSController.Broadcast(msg)
	// })

	NarutoAPIReverseProxy := newTrimPrefixReverseProxy(&url.URL{Scheme: "http", Host: "naruto-api", Path: "/api"}, "/api/naruto-api")

	handleForwardingToNarutoAPI := func(c *gin.Context) {
		NarutoAPIReverseProxy.ServeHTTP(c.Writer, c.Request)
	}

	var mainRouter *gin.Engine

	if certPath != "" && secretPath != "" {
		mainRouter = httpsRouter
	} else {
		mainRouter = httpRouter
	}

	routes := map[string]map[string]func(*gin.Context){
		"ANY": {
			"/api/naruto-api/*path": authenticatedRoute(handleForwardingToNarutoAPI),
		},
		"GET": {
			"/":                index,
			"/chat":            chat,
			"/naruto":          naruto,
			"/phone":           phone,
			"/ws/chat":         chatWSConnectionHandler,
			"/ws/phone/:token": authenticatedPhoneGetRoute(phoneWSConnectionHandler),
		},
		"POST": {
			"/login":                   handleAuthenticate,
			"/phone/login":             authenticatePhone,
			"/phone/sms":               phoneSMS(phoneWSController),
			"/phone/make/sms":          authenticatedPostRoute(makePhoneSMS(phoneWSController)),
			"/phone/get/conversations": authenticatedPostRoute(getPhoneConversations),
		},
	}

	methodMap := map[string]func(string, ...gin.HandlerFunc) gin.IRoutes{
		"ANY":  mainRouter.Any,
		"GET":  mainRouter.GET,
		"POST": mainRouter.POST,
	}

	// Register various routes with the main router
	for method, listOfHandlers := range routes {
		for route, handlerFunc := range listOfHandlers {
			methodMap[method](route, handlerFunc)
		}
	}

	/*for _, rjProject := range rjGlobal.Projects {
		if rjProject.SitePath != "" {
			httpsRouter.GET(rjProject.SitePath, func(c *gin.Context) {
				// ADJUST
			})
		}
	}

	firstRoute := httpRouter.Routes()[0]

	fmt.Println(firstRoute.Handler, firstRoute.Method, firstRoute.Path)*/

	if certPath != "" && secretPath != "" {
		// Register redirect route in HTTP router
		httpRouter.GET("/*path", func(c *gin.Context) {
			c.Redirect(302, "https://therileyjohnson.com/"+c.Param("path"))
		})

		httpsRouter.NoRoute(RjServe("/public", NewRjFileSystem("static/public/")))

		go httpsRouter.RunTLS(":443", certPath, secretPath)

		fmt.Println("Running http redirect server on", port)

		log.Fatal(httpRouter.Run(port))
	} else {
		httpRouter.NoRoute(RjServe("/public", NewRjFileSystem("static/public/")))

		fmt.Println("Running only the http server on", port)

		log.Fatal(httpRouter.Run(port))
	}
}
