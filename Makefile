cpu:
	sudo go test -bench=. -cpuprofile=cpu.out
mem:
	sudo go test -bench=. -benchmem -memprofile=mem.out
alloc:
	sudo go test -gcflags="-m"
c:
	go tool pprof cpu.out
m:
	go tool pprof mem.out
bench:
	sudo go test -bench=. -benchmem