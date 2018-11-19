# Get right directory context
cd /home/hippea9/RJNewSite
# Pull updates
git pull
# Kill running server instance
sudo rob kill
# Build the server and run it if building succeeds
sudo rob build --root && sudo nohup rob run &
