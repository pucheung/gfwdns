package main

import (
	"github.com/miekg/dns"
	"github.com/robfig/cron"
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
	crond := cron.New()
	spec := "* * 0 * * *"
	crond.AddFunc(spec, func(){
		h.Update(h.conf.UpdateUrl)
	})
	crond.Start()

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
		os.Remove(pidfile)
		os.Exit(1)
	}()

	startHttp(h)

	server := &dns.Server{Addr: ":53", Net: "udp4"}
	dns.HandleFunc(".", h.Do)
	server.ListenAndServe()

}
