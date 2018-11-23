package main

import (
	"github.com/miekg/dns"
	"os/exec"
)

func main() {
	h := new(Handle)
	h.Init()
	h.LoadFromFile()
	go h.UpdateCron()

	cmd := exec.Command(h.conf.IpsetPath)
	cmd.Run()

	startHttp(h)

	server := &dns.Server{Addr: ":53", Net: "udp4"}
	dns.HandleFunc(".", h.Do)
	server.ListenAndServe()

}
