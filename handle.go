package main

import (
	"bytes"
	"crypto/md5"
	"fmt"
	"github.com/miekg/dns"
	"github.com/patrickmn/go-cache"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

const (
	notIpQuery = 0
	_Ip4Query  = 4
	_Ip6Query  = 6
	REGSTR     = `([a-zA-Z0-9\-]+)\.(co\.jp|edu|gov|jp|tv|com|net|city|org|info|me|info|be|cc|io|us|im|la|ws|biz|de|kr|xyz|in|xxx|es|hk|gl)`
)

type Question struct {
	qname  string
	qtype  string
	qclass string
}

func (q *Question) String() string {
	return q.qname + q.qclass + q.qtype
}

type Handle struct {
	c    *cache.Cache
	conf *Config
}

func (h *Handle) Init() {
	c := cache.New(5*time.Minute, 10*time.Minute)
	conf := &Config{}
	conf.LoadConfig()
	h.c = c
	h.conf = conf
}

func (h *Handle) UpdateCron() {
	for {
		now := time.Now()
		next := now.Add(time.Hour * 24)
		next = time.Date(next.Year(), next.Month(), next.Day(), 0, 0, 0, 0, now.Location())
		t := time.NewTimer(next.Sub(now))
		<-t.C
		h.Update(h.conf.UpdateUrl)
	}
}

func (h *Handle) Do(w dns.ResponseWriter, req *dns.Msg) {
	dnsclient := new(dns.Client)
	q := req.Question[0]
	Q := Question{UnFqdn(q.Name), dns.TypeToString[q.Qtype], dns.ClassToString[q.Qclass]}
	ipQuery := h.isIpQuery(q)
	key := h.keyGen(Q.String())
	dtkey := h.keyGen(UnFqdn(q.Name))
	//fmt.Printf("domain :%v md5:[%s]\n", q.Name, dtkey)
	if ipQuery > 0 {
		data, found := h.c.Get(key)
		if found {
			msg := new(dns.Msg)
			msg.Unpack(data.([]byte))
			msg.Id = req.Id
			w.WriteMsg(msg)
		} else {
			dtype := h.checkDomain(dtkey, UnFqdn(q.Name))
			//	fmt.Printf("Find %s Type [%s]", UnFqdn(q.Name), dtype)
			switch dtype {
			case "adb":
				msg := new(dns.Msg)
				msg.SetReply(req)
				switch ipQuery {
				case _Ip4Query:
					rr_header := dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    3000,
					}
					a := &dns.A{rr_header, net.ParseIP("127.0.0.1")}
					msg.Answer = append(msg.Answer, a)
				case _Ip6Query:
					rr_header := dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeAAAA,
						Class:  dns.ClassINET,
						Ttl:    3000,
					}
					a := &dns.AAAA{rr_header, net.ParseIP("::1")}
					msg.Answer = append(msg.Answer, a)
				}
				data, err := msg.Pack()
				if err != nil {
					log.Printf("Pack %v", err)
				} else {
					h.c.Set(key, data, cache.NoExpiration)
					h.c.SaveFile(h.conf.CacheDbPath)
				}
				w.WriteMsg(msg)
			case "gfw":
				msg, _, err := dnsclient.Exchange(req, h.conf.GfwDns+":53")
				if err == nil {
					data, err := msg.Pack()
					if err != nil {
						log.Printf("Pack %v", err)
					}
					h.c.Set(key, data, cache.DefaultExpiration)
					for _, a := range msg.Answer {
						switch ipQuery {
						case _Ip4Query:
							if ip, ok := a.(*dns.A); ok {
								cmd := exec.Command(h.conf.IpSetPath,  ip.A.String())
								cmd.Run()
							}
						case _Ip6Query:
							if ip, ok := a.(*dns.AAAA); ok {
								cmd := exec.Command(h.conf.IpSetPath, ip.AAAA.String())
								cmd.Run()
							}
						}
					}
					w.WriteMsg(msg)
				} else {
					log.Printf("GFW Dns %v", err)
					dns.HandleFailed(w, req)
				}
			case "normal":
				msg, _, err := dnsclient.Exchange(req, h.conf.ChinaDns+":53")
				if err == nil {
					data, err := msg.Pack()
					if err != nil {
						log.Printf("Pack %v", err)
					}
					h.c.Set(key, data, cache.DefaultExpiration)
					w.WriteMsg(msg)
				} else {

					log.Printf("China Dns %v", err)
					dns.HandleFailed(w, req)
				}
			case "host":
				hkey := h.keyGen(UnFqdn(q.Name) + "ip")
				ip, _ := h.c.Get(hkey)
				msg := new(dns.Msg)
				msg.SetReply(req)
				switch ipQuery {
				case _Ip4Query:
					rr_header := dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    3000,
					}
					a := &dns.A{rr_header, net.ParseIP(ip.(string))}
					msg.Answer = append(msg.Answer, a)
				case _Ip6Query:
					rr_header := dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeAAAA,
						Class:  dns.ClassINET,
						Ttl:    3000,
					}
					a := &dns.AAAA{rr_header, net.ParseIP(ip.(string))}
					msg.Answer = append(msg.Answer, a)
				}

				data, err := msg.Pack()
				if err != nil {
					log.Printf("Pack %v", err)
				} else {
					h.c.Set(key, data, cache.NoExpiration)
					h.c.SaveFile(h.conf.CacheDbPath)
				}
				w.WriteMsg(msg)

			}
		}
	} else {
		msg, _, err := dnsclient.Exchange(req, h.conf.ChinaDns+":53")
		if err == nil {
			w.WriteMsg(msg)
		} else {

			log.Printf("Query %v", err)
			dns.HandleFailed(w, req)
		}
	}
}

func (h *Handle) checkDomain(dtkey, domain string) string {
	dtype, found := h.c.Get(dtkey)
	if found {
		return dtype.(string)
	}
	reg := regexp.MustCompile(REGSTR)
	find := reg.FindString(domain)
	if find == "" {
		return "normal"
	}
	dtkey = h.keyGen(find)
	dtype, found = h.c.Get(dtkey)
	if found {
		return dtype.(string)
	}
	return	"normal"
}

func (h *Handle) isIpQuery(q dns.Question) int {
	if q.Qclass != dns.ClassINET {
		return notIpQuery
	}
	switch q.Qtype {
	case dns.TypeA:
		return _Ip4Query
	case dns.TypeAAAA:
		return _Ip6Query
	default:
		return notIpQuery
	}
}

func (h *Handle) keyGen(q string) string {
	md := md5.New()
	md.Write([]byte(q))
	x := md.Sum(nil)
	key := fmt.Sprintf("%x", x)
	return key
}

func (h *Handle) LoadFromFile() {
	h.c.LoadFile(h.conf.CacheDbPath)
}

func (h *Handle) Update(url string) {

	resp, err := http.Get(url)
	if err != nil {
		log.Printf("Http %s", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		data, herr := ioutil.ReadAll(resp.Body)
		if herr != nil {
			log.Printf("Read %s err %s", url, herr)
		}

		//Read Line From data Buf And split string use '/'

		buf := bytes.NewBuffer(data)
		for {
			line, err := buf.ReadString(byte('\n'))
			if err != nil || err == io.EOF {
				break
			}
			domain := strings.Split(line, "/")
			dtype := string(strings.Replace(domain[0], "\n", "", -1))
			dom := string(strings.Replace(domain[1], "\n", "", -1))
			key := h.keyGen(dom)
			h.c.Set(key, dtype, cache.NoExpiration)
			//fmt.Printf("%s [%s]\n", dom, dtype)
		}
		h.c.SaveFile(h.conf.CacheDbPath)
	}
}

func (h *Handle) Set(domain, dtype string) {
	key := h.keyGen(domain)
	Q1 := Question{domain, dns.TypeToString[dns.TypeA], dns.ClassToString[dns.ClassINET]}
	Q2 := Question{domain, dns.TypeToString[dns.TypeAAAA], dns.ClassToString[dns.ClassINET]}
	key1 := h.keyGen(Q1.String())
	key2 := h.keyGen(Q2.String())
	h.c.Set(key, dtype, cache.NoExpiration)
	h.c.Delete(key1)
	h.c.Delete(key2)
	h.c.SaveFile(h.conf.CacheDbPath)
}

func (h *Handle) Del(domain string) {
	key := h.keyGen(domain)
	q1 := Question{domain, dns.TypeToString[dns.TypeA], dns.ClassToString[dns.ClassINET]}
	q2 := Question{domain, dns.TypeToString[dns.TypeAAAA], dns.ClassToString[dns.ClassINET]}
	key1 := h.keyGen(q1.String())
	key2 := h.keyGen(q2.String())
	h.c.Delete(key)
	h.c.Delete(key1)
	h.c.Delete(key2)
	h.c.SaveFile(h.conf.CacheDbPath)
}

func (h *Handle) AddHost(domain, ip string) {
	keyType := h.keyGen(domain)
	keyCache := h.keyGen(domain + "ip")
	h.c.Set(keyType, "host", cache.NoExpiration)
	h.c.Set(keyCache, ip, cache.NoExpiration)
	h.c.SaveFile(h.conf.CacheDbPath)

}
func UnFqdn(s string) string {
	if dns.IsFqdn(s) {
		return s[:len(s)-1]
	}
	return s
}
