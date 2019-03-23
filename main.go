package main

import (
  "github.com/zepryspet/RePAN/utils"
  "github.com/gorilla/mux"
  "log"
  "net/http"
  "encoding/json"
  "io/ioutil"
)

func main() {
  router := mux.NewRouter()
  router.HandleFunc("/", GetIndex).Methods("GET")
  router.HandleFunc("/rules", Showrules).Methods("POST")
  router.HandleFunc("/getapi", GetAPI).Methods("POST")
  log.Fatal(http.ListenAndServe("127.0.0.1:8000", router))
}

func GetIndex(w http.ResponseWriter, r *http.Request){
  Html, err := ioutil.ReadFile("index.html") // just pass the file name
  if err != nil {
      pan.Logerror(err, true)
  }
  // Sending it:
  w.Write(Html)  // w is an io.Writer
}

func Showrules(w http.ResponseWriter, r *http.Request){
  firewall := new(pan.Fw)
  if r.Body == nil {
    http.Error(w, "Please send a request body", 400)
    return
  }
  err := json.NewDecoder(r.Body).Decode(&firewall)
  if err != nil {
    http.Error(w, err.Error(), 400)
    return
  }
  CheckRules := pan.RuleObj{
    Action: "get",
    Location:"vsys",
    Vsys: "vsys1",
  }
  pan.RuleEnf(&CheckRules, firewall)
  result, e := json.MarshalIndent(CheckRules.Rules, "", "    ")
  if e != nil {
    http.Error(w, err.Error(), 400)
    return
  }
  w.Write( (result))
  //json.NewEncoder(w).Encode(CheckRules.Rules)
}

func GetAPI(w http.ResponseWriter, r *http.Request){
  firewall := new(pan.Fw)
  if r.Body == nil {
    http.Error(w, "Please send a request body", 400)
    return
  }
  err := json.NewDecoder(r.Body).Decode(&firewall)
  if err != nil {
    http.Error(w, err.Error(), 400)
    return
  }
  //fmt.Println(u.Id)
  //v := r.Form
  pan.Keygen(firewall)
  //println(firewall.Api)
  if firewall.Api == ""{
    http.Error(w, "Failed to generate API", 400)
  }else{
    w.Write([]byte (firewall.Api))
  }
}
