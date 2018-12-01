package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
)

type Config struct {
	ChinaDns     string
	GfwDns       string
	UpdateUrl    string
	CacheDbPath  string
	IpSetPath    string
	FireWallPath string
	WebuiPath    string
}

func (config *Config) LoadConfig() {
	f, err := os.OpenFile("/usr/local/etc/godns/config.json", os.O_RDONLY, os.ModePerm)
	if err != nil {
		fmt.Printf("%v\n", err)
		return
	}
	data, err := ioutil.ReadAll(f)
	if err != nil {
		fmt.Printf("%v\n", err)
		return
	}
	err = json.Unmarshal([]byte(data), &config)
	if err != nil {
		fmt.Printf("%v\n", err)
		return
	}
}
