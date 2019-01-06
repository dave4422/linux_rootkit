#append mounting info for ftrace, according to https://www.kernel.org/doc/Documentation/trace/ftrace.txt
#mounting worked for me, only need to be done 
sudo echo "tracefs       /sys/kernel/tracing       tracefs defaults        0       0" >> /etc/fstab
#might not work to echo into /etc/fstab, entry must then be set manually