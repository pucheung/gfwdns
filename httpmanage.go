package main

import (
	"fmt"
	"net/http"
)

type HttpManage struct {
	h *Handle
}

func (hm *HttpManage) addHost(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	values := r.Form
	host := values.Get("host")
	ip := values.Get("ip")
	hm.h.AddHost(host, ip)
	fmt.Fprintf(w, "AddHost %s IP [%s]", host, ip)
}

func (hm *HttpManage) addDomain(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	values := r.Form
	domain := values.Get("domain")
	dtype := values.Get("type")
	hm.h.Set(domain, dtype)
	fmt.Fprintf(w, "AddDomain %s Type [%s]", domain, dtype)
}

func (hm *HttpManage) update(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	values := r.Form
	url := values.Get("url")
	hm.h.Update(url)
	fmt.Fprintf(w, "Update Url %s", url)
}

func (hm *HttpManage) delete(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	values := r.Form
	domain := values.Get("domain")
	hm.h.Del(domain)
	fmt.Fprintf(w, "DelDomain %s", domain)
}

func startHttp(h *Handle) {
	hm := new(HttpManage)
	hm.h = h
	http.HandleFunc("/addHost", hm.addHost)
	http.HandleFunc("/addDomain", hm.addDomain)
	http.HandleFunc("/update", hm.update)
	http.HandleFunc("/delDomain", hm.delete)
	http.Handle("/", http.StripPrefix("/", http.FileServer(http.Dir(h.conf.WebuiPath))))

	go http.ListenAndServe("0.0.0.0:8081", nil)

}
