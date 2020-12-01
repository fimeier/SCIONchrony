package main

var fdList = make(map[int]int)
var maxFD = 1024

func GetFreeFD() int {
	for fd := 1; fd <= maxFD; fd++ {
		if fdList[fd] == 0 {
			fdList[fd] = 1
			return fd
		}

	}
	return -1
}

func DeleteFD(fd int) {
	fdList[fd] = 0
}

func main() {
	println("There is nothing to do here....")
	println("First free FD", GetFreeFD())
	println("free FD", GetFreeFD())
	println("free FD", GetFreeFD())
	println("free FD", GetFreeFD())
	println("free FD", GetFreeFD())
	DeleteFD(1)
	println("free FD", GetFreeFD())
	println("free FD", GetFreeFD())
	println("free FD", GetFreeFD())
}
