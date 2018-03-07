package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/olahol/melody"
	mailgun "gopkg.in/mailgun/mailgun-go.v1"
)

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

func serveFile(c *gin.Context) {
	if strings.HasSuffix(c.Request.URL.Path, "rjResume.pdf") {
		addr := getIPAdress(c.Request)
		mux.Lock()
		seen := resumeRequesters[addr]
		resumeRequesters[addr]++
		myEmail := mEmail
		lmg := mg
		mux.Unlock()
		if seen == 0 {
			_, _, err := lmg.Send(mailgun.NewMessage("robot@mail.therileyjohnson.com", fmt.Sprintf("Someone at %s Downloaded Your Resume", addr), "See the title dummy", myEmail))
			if err != nil {
				fmt.Println("Error sending email to yourself")
			}
		}
	}
	http.ServeFile(c.Writer, c.Request, "./static"+c.Request.URL.Path)
}

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

type message struct {
	Pi      bool   `json:"pi"`
	Message string `json:"message"`
}

//Struct to hold the private and public keys for the MailGun API
type info struct {
	Private    string `json:"private"`
	Public     string `json:"public"`
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
var mEmail, port string
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

	var information info

	if fi, err = ioutil.ReadFile("../keys.json"); err != nil {
		log.Fatal("Error reading keys data")
	} else {
		json.Unmarshal(fi, &information)
	}

	mg = mailgun.NewMailgun(information.MailServer, information.Private, information.Public)
	mEmail = information.MyEmail

	if information.Production {
		port = information.ProPort
	} else {
		port = information.DevPort
	}
}

func main() {
	r := gin.Default()
	mc := melody.New()
	r.GET("/", index)
	r.GET("/chat", chat)
	r.GET("/public/", serveFile)
	r.GET("/sms", sms)
	r.GET("/wschat", func(c *gin.Context) {
		mc.HandleRequest(c.Writer, c.Request)
	})
	mc.HandleMessage(func(s *melody.Session, msg []byte) {
		mc.Broadcast(msg)
	})
	log.Fatal(r.Run(port))
}
