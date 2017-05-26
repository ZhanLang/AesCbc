package main

import "fmt";
import "github.com/zhanlang/AesCbc";

func main()  {
	des, err := AesCbc.EncryptionAES("asdfwetyhjuytrfd", "gfdertfghjkuyrtg", []byte(string("dfeadf")));
	if err == nil {
		fmt.Println(des);
	}

	src, err := AesCbc.DecryptionAES("asdfwetyhjuytrfd", "gfdertfghjkuyrtg", des);
	if err == nil {
		fmt.Println(string(src));
	}
}
