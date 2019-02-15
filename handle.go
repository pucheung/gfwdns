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
	REGSTR     = `([a-zA-Z0-9\-]+)\.(ac|ad|ae|af|al|am|as|at|az|ba|be|bf|bg|bi|bj|bs|bt|by|ca|cat|cd|cf|cg|ch|ci|cl|cm|co\.ao|co\.bw|co\.ck|co\.cr|co\.id|co\.il|co\.in|co\.jp|co\.ke|co\.kr|co\.ls|co\.ma|com|com\.af|com\.ag|com\.ai|com\.ar|com\.au|com\.bd|com\.bh|com\.bn|com\.bo|com\.br|com\.bz|com\.co|com\.cu|com\.cy|com\.do|com\.ec|com\.eg|com\.et|com\.fj|com\.gh|com\.gi|com\.gt|com\.hk|com\.jm|com\.kh|com\.kw|com\.lb|com\.ly|com\.mm|com\.mt|com\.mx|com\.my|com\.na|com\.nf|com\.ng|com\.ni|com\.np|com\.om|com\.pa|com\.pe|com\.pg|com\.ph|com\.pk|com\.pr|com\.py|com\.qa|com\.sa|com\.sb|com\.sg|com\.sl|com\.sv|com\.tj|com\.tr|com\.tw|com\.ua|com\.uy|com\.vc|com\.vn|co\.mz|co\.nz|co\.th|co\.tz|co\.ug|co\.uk|co\.uz|co\.ve|co\.vi|co\.za|co\.zm|co\.zw|cv|cz|de|dj|dk|dm|dz|ee|es|eu|fi|fm|fr|ga|ge|gg|gl|gm|gp|gr|gy|hk|hn|hr|ht|hu|ie|im|iq|is|it|it\.ao|je|jo|kg|ki|kz|la|li|lk|lt|lu|lv|md|me|mg|mk|ml|mn|ms|mu|mv|mw|mx|ne|nl|no|nr|nu|org|pl|pn|ps|pt|ro|rs|ru|rw|sc|se|sh|si|sk|sm|sn|so|sr|st|td|tg|tk|tl|tm|tn|to|tt|us|vg|vn|vu|ws)`
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
	c := cache.New(5*time.Minute, 5*time.Minute)
	conf := &Config{}
	conf.LoadConfig()
	h.c = c
	h.conf = conf
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
								cmd := exec.Command(h.conf.IpSetPath, ip.A.String())
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
	return "normal"
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
		log.Printf("Get UpdateUrl Error %s", err)
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
