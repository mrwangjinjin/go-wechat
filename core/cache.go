package core

import (
	"encoding/json"
	"github.com/gomodule/redigo/redis"
	"time"
)

// Cache
type Cache interface {
	Set(key string, val interface{}) error
	SetEx(key string, val interface{}, expires int64) error
	Get(key string) ([]byte, error)
	Exists(key string) bool
}

// CacheConfig
type CacheConfig struct {
	MaxIdle     int
	MaxActive   int
	IdleTimeout time.Duration
	Host        string
	Auth        string
}

type CacheDefault struct {
	redis *redis.Pool
}

func NewCache(config *CacheConfig) *CacheDefault {
	return &CacheDefault{
		redis: &redis.Pool{
			MaxIdle:     config.MaxIdle,
			MaxActive:   config.MaxActive,
			IdleTimeout: config.IdleTimeout,
			Dial: func() (redis.Conn, error) {
				c, err := redis.Dial("tcp", config.Host)
				if err != nil {
					return nil, err
				}
				if config.Auth != "" {
					if _, err := c.Do("AUTH", config.Auth); err != nil {
						_ = c.Close()
						return nil, err
					}
				}
				return c, err
			},
			TestOnBorrow: func(c redis.Conn, t time.Time) error {
				_, err := c.Do("PING")
				return err
			},
		},
	}
}

func (self *CacheDefault) Set(key string, val interface{}) error {
	conn := self.redis.Get()
	defer func() {
		_ = conn.Close()
	}()

	value, err := json.Marshal(val)
	if err != nil {
		return err
	}

	_, err = conn.Do("SET", key, value)
	if err != nil {
		return err
	}

	return nil
}

func (self *CacheDefault) SetEx(key string, val interface{}, expires int64) error {
	conn := self.redis.Get()
	defer func() {
		_ = conn.Close()
	}()

	value, err := json.Marshal(val)
	if err != nil {
		return err
	}

	_, err = conn.Do("SET", key, value)
	if err != nil {
		return err
	}

	_, err = conn.Do("EXPIRE", key, expires)
	if err != nil {
		return err
	}

	return nil
}

func (self *CacheDefault) Get(key string) (reply []byte, err error) {
	conn := self.redis.Get()
	defer func() {
		_ = conn.Close()
	}()

	reply, err = redis.Bytes(conn.Do("GET", key))
	if err != nil {
		return nil, err
	}

	return reply, nil
}

func (self *CacheDefault) Exists(key string) bool {
	conn := self.redis.Get()
	defer func() {
		_ = conn.Close()
	}()

	exists, err := redis.Bool(conn.Do("EXISTS", key))
	if err != nil {
		return false
	}

	return exists
}
