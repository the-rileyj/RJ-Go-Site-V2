git pull
if go build index.go ; then
	killall -9 index
	nohup sudo ./index &
else
	echo "Failed to compile"
fi
