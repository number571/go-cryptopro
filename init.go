package main

import (
	"fmt"
	"os/exec"
	"runtime"
)

func main() {
	if runtime.GOOS != "linux" {
		panic("error: support only linux platform")
	}
	// -createcert: create certificate request, send it to CA;
	// -provtype:
	// 	80	GOST R 34.10-2012 (256) Signature with Diffie-Hellman Key Exchange;
	// 	81	GOST R 34.10-2012 (512) Signature with Diffie-Hellman Key Exchange;
	// -rdn: CN (certificate name);
	// -cont: container's path;
	// -pin: key container password;
	// -ku: use user container (CURRENT_USER);
	// -du: install into user store (CURRENT_USER);
	// -ex: create/use exchange key;
	// -ca: specify Microsoft CA URL;
	exec.Command(
		"sh",
		"-c",
		fmt.Sprintf(
			// -ca http://cryptopro.ru/certsrv
			"/opt/cprocsp/bin/amd64/cryptcp -creatcert -pin \"%s\" -provtype %d -rdn \"CN=%s\" -cont \"\\\\\\\\.\\\\HDIMAGE\\\\%s\" -ku -du -ex",
			"init_password",
			80,
			"init_subject",
			"init_container",
		),
	).Run()
}
