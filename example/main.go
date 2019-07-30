package main

import (
	"github.com/mrwangjinjin/go-wechat/core"
	"log"
	"net/http"
	"time"
)

func main() {
	cache := core.NewCache(&core.CacheConfig{
		MaxIdle:     30,
		MaxActive:   30,
		IdleTimeout: time.Duration(time.Second * 200),
		Host:        "127.0.0.1:6379",
		Auth:        "",
	})
	config := &core.ClientConfig{
		AppId:     "",
		AppSecret: "",
		Token:     "",
		AesKey:    "",
		BaseUrl:   "https://api.weixin.qq.com",
	}
	server := core.NewServer(config, cache)
	http.HandleFunc("/api/notify", func(w http.ResponseWriter, r *http.Request) {
		server.Serve(w, r)
	})
	http.HandleFunc("/api/event", func(w http.ResponseWriter, r *http.Request) {
		server.EventServe(w, r)
	})
	log.Println("Server listen at 127.0.0.1:9595")
	err := http.ListenAndServe("127.0.0.1:9595", nil)
	if err != nil {
		log.Println(err)
	}
}
