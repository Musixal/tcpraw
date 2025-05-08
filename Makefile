cpu:
	 go test -bench=. -cpuprofile=cpu.out
mem:
	 go test -bench=. -benchmem -memprofile=mem.out
alloc:
	 go test -gcflags="-m"
c:
	go tool pprof cpu.out
m:
	go tool pprof mem.out
bench:
	 go test -bench=. -benchmem