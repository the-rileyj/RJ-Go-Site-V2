git pull
if go build rj_server.go ; then
	killall -9 rj_server
	nohup sudo ./rj_server &
else
	echo "Failed to compile"
fi
