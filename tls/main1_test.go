package tls

import (
	"testing"
)

func TestServer1(t *testing.T){
	_,err :=Dial("tcp", "www.baidu.com:443", nil)
	if err != nil{
		t.Errorf("failed to dail to www.baidu.com:443, ret:%s\n", err.Error())
	}
}

