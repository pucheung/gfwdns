package main

import (
	"github.com/miekg/dns"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"io/ioutil"
	"strconv"
)

var sigs = make(chan os.Signal, 1)
var pidfile = "/var/log/godns.pid"

func main() {
	h := new(Handle)
	h.Init()
	h.LoadFromFile()
	go h.UpdateCron()

	if pid := syscall.Getpid(); pid != 1{
		ioutil.WriteFile(pidfile, []byte(strconv.Itoa(pid)), 0777)
	}

	cmd := exec.Command(h.conf.UpScript)
	cmd.Run()

	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func(){
		<-sigs
		cmd := exec.Command(h.conf.DownScript)
		cmd.Run()
		os.Remove(pidfile)
		os.Exit(1)
	}()

	startHttp(h)

	server := &dns.Server{Addr: ":53", Net: "udp4"}
	dns.HandleFunc(".", h.Do)
	server.ListenAndServe()

}
