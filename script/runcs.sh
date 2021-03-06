echo "kill running nc"
killall nc

# listen on port 9000
echo "listening on port 9000"
nc -l 9000 &
sleep 1

# connect to proxy at port 4443
echo "openssl connect"
openssl s_client -ciphersuites TLS_AES_128_GCM_SHA256 -msg -state -debug -security_debug_verbose -keylogfile key.log -connect localhost:4443

