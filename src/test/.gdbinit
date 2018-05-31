#filename dk-client-debug
target remote:1234
file "~/workspace/tdog/src/test/hello"
b main
c
