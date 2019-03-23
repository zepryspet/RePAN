package pan

import (
        "net/http"
        "log"
        "crypto/tls"
        "io/ioutil"
        "time"
        "encoding/json"
        //"bytes"
        "fmt"
        "github.com/beevik/etree"
        "net/url"
        "errors"
        "os"
        "strconv"
)

type Fw struct{
  Ip    string  `json:"firewall"`
  Api   string  `json:"api"`
  User  string  `json:"user"`
  Pass  string  `json:"password"`
}

type RuleObj struct{
  Action    string
  Location  string
  Vsys      string
  Dg        string
  Where     string
  Rules     Entry
}

type Entry struct {
  Entries []Rulebase `json:"entry"`
}
type Rulebase struct{ //this will include newname in case rename is needed
  Name    string   `json:"@name"`
  From    Member   `json:"from"`
  To      Member   `json:"to"`
  Source  Member   `json:"source"`
  Suser   Member   `json:"source-user"`
  Dst     Member   `json:"destination"`
  Srv     Member   `json:"service"`
  UrlCat  Member   `json:"category"`
  App     Member   `json:"application"`
  Schdl   Member   `json:"schedule"`
  Tag     Member   `json:"tag"`
  NegS    string   `json:"negate-source"`
  NegD    string   `json:"negate-destination"`
  Disable string   `json:"disabled"`
  Description string   `json:"description"`
  Gtag    string   `json:"group-tag"`
  Hip     Member   `json:"hip-profiles"`
  Action  string   `json:"action"`
  Icmp    string   `json:"icmp-unreachable"`
  Type    string   `json:"rule-type"`
  LogFwd  string   `json:"log-setting"`
  LogStart  string   `json:"log-start"`
  LogEnd  string   `json:"log-end"`
  Qos     interface{}  `json:"qos"`
  Option  interface{}  `json:"option"`
}

type Member struct{
  Member []string `json:"member"`
}

type SecProf struct{
  Profiles interface{} `json:"profiles"`
  Group   Member `json:"group"`
}



//Function to generate an API key
func Keygen(firewall *Fw) {
    apiKey := ""

    //Validating that all login flags are set
    if (firewall.Ip == "" || firewall.User =="" || firewall.Pass=="") {
        e := "Error: required flags \"ip-address\", \"password\" or \"user\" not set"
        println (e)
        Logerror(errors.New(e), false)
        return
    }
	//Defining secondary variables
	req, err := url.Parse("https://" + firewall.Ip + "/api/?")
	if err != nil {
		Logerror(err, false)
	}
	q := url.Values{}
	q.Add("password", firewall.Pass)
	q.Add("user", firewall.User)
	q.Add("type", "keygen")
	req.RawQuery = q.Encode()
    resp, err := HttpValidate(req.String(), false)
    if err != nil {
		Logerror(err, false)
    return
	}
    doc := etree.NewDocument()
    doc.ReadFromBytes(resp)
    for _, e := range doc.FindElements("./response/result/*") {
        apiKey = e.Text()
    }
    firewall.Api = apiKey
}

func HttpValidate (req string, debug bool) ([]byte , error) {
    //Initialazing the error it'll return if anyone it's found.
    var problem error
    //HTTP requests are print in case debug flag is set
    if debug{
        println(req)
    }
    //Ignoring TLS certificate checking
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	//Setting HTTP timeout as 15 seconds.
	netClient := &http.Client{
		Timeout:   time.Second * 15,
		Transport: tr,
	}

  resp, err := netClient.Get(req)
	if err != nil {
		Logerror(err, false)
    return []byte(""), err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		Logerror(err, false)
    return []byte(""), err
	}
	//making sure the API responds with a 200 code and a success on it
    if resp.StatusCode == 200 {
		doc := etree.NewDocument()
		doc.ReadFromBytes(body)
        //extraccting the response status from the http response and comparing it with "success"
        status := doc.FindElement("./*").SelectAttrValue("status", "unknown")
        if status != "success"{
            problem = errors.New("error with HTTP request:\t" + req + "\nreceived status " + status +  " and response :\t" + string(body))
        }
	}else {
        problem = errors.New("error with HTTP request:\t" + req + "\nreceived status code:\t" + strconv.Itoa(resp.StatusCode))
	}

    return body,problem
}

func RuleEnf (WhatToDo *RuleObj, firewall *Fw) {
  println(WhatToDo.Action)
  //Ignoring TLS certificate checking
  tr := &http.Transport{
    TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
  }
  //Setting HTTP timeout as 15 seconds.
  netClient := &http.Client{
    Timeout:   time.Second * 15,
    Transport: tr,
  }
  //Defining secondary variables
  req, err := url.Parse("https://"+firewall.Ip+"/restapi/9.0/Policies/SecurityRules")
  if err != nil {
    Logerror(err, false)
    return
  }
  q := url.Values{}
  q.Add("location", WhatToDo.Location)
  q.Add("vsys", WhatToDo.Vsys)
  //q.Add("type", "keygen")
  req.RawQuery = q.Encode()
  //Creating a new request
  request, err := http.NewRequest("GET", req.String(), nil)
  //Adding auth Header
  request.Header.Set("X-PAN-KEY", firewall.Api)
  //Sending request
  resp, err := netClient.Do(request)
  //resp, err := netClient.Post(req, "application/json", bytes.NewBuffer(bytesRepresentation))
  if err != nil {
    log.Fatalln(err)
  }

  //var result map[string]interface{}
  type Result struct {
    Status string `json:"@status"`
    Code string `json:"@code"`
    Result *json.RawMessage `json:"result"`
  }
  r:= new(Result)
  json.NewDecoder(resp.Body).Decode(&r)
  type Entries struct {
    Tcount string `json:"@total-count"`
    Count string `json:"@count"`
    Entries *json.RawMessage `json:"entry"`
  }
  e:= new(Entries)
  err = json.Unmarshal(*r.Result, &e)
  //var s interface{}
  err = json.Unmarshal(*r.Result, &WhatToDo.Rules)
  //log.Println(r)
  //err = json.Unmarshal(*s, &WhatToDo.Rules)
  if r.Status == "success"{
    //log.Println(e)
    //log.Println(s)
    log.Println(WhatToDo.Rules)
  }
  //log.Println(Result["data"])
}


//Prints the error and exit execution if fatal is set
func Logerror(err error, fatal bool) {
	if err != nil {
		//Wlog("error.txt", err.Error(), true)
		fmt.Println (err.Error())
        if fatal{
		  		os.Exit(1)
        }
	}
}
