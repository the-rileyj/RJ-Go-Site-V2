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
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/gin-contrib/static"
	"github.com/gin-gonic/gin"
	"github.com/olahol/melody"
	mailgun "gopkg.in/mailgun/mailgun-go.v1"
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
	fi, err := os.Open("../keys.json")

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

	return ioutil.WriteFile("../keys.json", informationBytes, 0644)
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

func sms(c *gin.Context) {
	fmt.Println(1, c.Request.URL.Query()["AccountSid"])
	fmt.Println(2, c.Request.URL.Query()["accountsid"])
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
		go writeStructToJSON(vT, "../numer.json")
	}

	executeTemplate(c.Writer, "index.gohtml", vT)
}

func kdsuIP(c *gin.Context) {
	information, err := getInfo()

	if err != nil {
		c.Writer.Write([]byte(fmt.Sprintf("ERROR: %s", err.Error())))
		return
	}

	executeTemplate(c.Writer, "kdsuIP.gohtml", information.KdsuIP)
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
var mux sync.Mutex
var mg mailgun.Mailgun
var certPath, mEmail, port, secretPath string
var resumeRequesters map[string]int

func init() {
	rand.Seed(time.Now().UTC().UnixNano())
	resumeRequesters = make(map[string]int)
	fi, err := ioutil.ReadFile("../numer.json")

	if err == nil {
		json.Unmarshal(fi, &vT)
	} else {
		vT = visiTracker{0, 0, []string{}}
	}

	tpl = template.Must(template.New("").Funcs(template.FuncMap{"snapCode": getSnap}).ParseGlob("templates/*.gohtml"))

	information, err := getInfo()

	mg = mailgun.NewMailgun(information.MailServer, information.Private, information.Public)
	mEmail = information.MyEmail

	certPath = information.CertPath
	secretPath = information.SecretPath

	if information.Production {
		port = information.ProPort
	} else {
		port = information.DevPort
	}
}

func main() {
	rjGlobal, err := getRjGlobal("./")

	if err != nil {
		log.Fatal(err)
	}

	httpsRouter := gin.Default()
	httpRouter := gin.Default()
	mc := melody.New()
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
	httpsRouter.GET("/kdsu_addr", kdsuIP)

	httpsRouter.POST("/kdsu_addr", func(c *gin.Context) {
		var IPupdater ipUpdate

		decoder := json.NewDecoder(c.Request.Body)

		err := decoder.Decode(&IPupdater)

		if err != nil {
			c.Writer.Write([]byte("FAILURE"))
			return
		}

		if IPupdater.Error != "" {
			c.Writer.Write([]byte("FAILURE"))
			return
		}

		information, err := getInfo()

		if err != nil {
			c.Writer.Write([]byte("FAILURE"))
			return
		}

		if postIP := getIPAdress(c.Request); !strings.Contains(postIP, "138.247.") {
			fmt.Println(postIP)
			c.Writer.Write([]byte("FAILURE"))
			return
		}

		information.KdsuIP = IPupdater.IP

		err = writeInfo(information)

		if err != nil {
			c.Writer.Write([]byte("FAILURE"))
			return
		}

		c.Writer.Write([]byte("SUCCESS"))
	})

	httpRouter.GET("/*path", func(c *gin.Context) {
		c.Redirect(302, "https://therileyjohnson.com/"+c.Param("variable"))
	})

	// HTTPS Routes:
	httpsRouter.GET("/", index)
	httpsRouter.GET("/chat", chat)
	httpsRouter.GET("/sms", sms)
	httpsRouter.GET("/wschat", func(c *gin.Context) {
		mc.HandleRequest(c.Writer, c.Request)
	})
	mc.HandleMessage(func(s *melody.Session, msg []byte) {
		mc.Broadcast(msg)
	})

	for _, rjProject := range rjGlobal.Projects {
		if rjProject.SitePath != "" {
			httpsRouter.GET(rjProject.SitePath, func(c *gin.Context) {
				// ADJUST
			})
		}
	}

	httpsRouter.NoRoute(RjServe("/public", NewRjFileSystem("static/public/")))

	if certPath != "" && secretPath != "" {
		go httpsRouter.RunTLS(":443", certPath, secretPath)
		fmt.Println("Running http redirect server on", port)
		log.Fatal(httpRouter.Run(port))
	} else {
		fmt.Println("Running only the http server on", port)
		log.Fatal(httpsRouter.Run(port))
	}
}
