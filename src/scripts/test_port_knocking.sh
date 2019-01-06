#this scriipt can be used to test portknocking after the module
# has been loaded into the kernel
#listen to port 1100
echo "start to listen to port 1100"
nc -l -p 1100 &
#Hide port 1100
echo "Make sure control program is compiled"
gcc -o control control_program.c
echo "hide port 1100"
./control -port_knocking 1100
#call knocking ports
echo "call 1500 2000 2500 in this order"
nc localhost 1500
nc localhost 2000
nc localhost 2500
echo "Now you can connect to port 1100, use ctrl + Z to exit script and nc localhost 1100 to establish connection"
#nc localhost 1100
