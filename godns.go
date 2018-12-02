package main

import (
	"github.com/miekg/dns"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"strconv"
	"log"
)


var sigs = make(chan os.Signal, 1)
var pidfile = "/var/run/godns.pid"

func main() {
	h := new(Handle)
	h.Init()
	h.LoadFromFile()
	go h.UpdateCron()

	if pid := syscall.Getpid(); pid != 1{
		fpid, err := os.OpenFile(pidfile,os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
		defer fpid.Close()
		if err != nil {
			log.Printf("Open PidFile Error %v\n", err)
			return
		}
		fpid.Write([]byte(strconv.Itoa(pid)))
	}

	cmd := exec.Command(h.conf.UpScript)
	cmd.Run()

	signal.Notify(sigs, syscall.SIGKILL, syscall.SIGTERM)
	go func(){
		<-sigs
		cmd := exec.Command(h.conf.DownScript)
		err := cmd.Run()
		if err != nil {
			log.Printf("DownScript Error %v", err)
		}
		os.Remove(pidfile)
		os.Exit(1)
	}()

	startHttp(h)

	server := &dns.Server{Addr: ":53", Net: "udp4"}
	dns.HandleFunc(".", h.Do)
	server.ListenAndServe()

}
