#demonstrate that this file can not be opened
nano /var/log/kern.log
#return the own PID and store it in a tmp file
echo $$ > .tmp_pe_script
./control -privilege_pid < .tmp_pe_script
rm .tmp_pe_script
#show that opening the file is possbivle now
nano /var/log/kern.log