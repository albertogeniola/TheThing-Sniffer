#!/bin/bash
# Init

DEST_DIR=/usr/share/MiddleRouter
GIT_REPO=https://albertogeniola@bitbucket.org/aaltopuppaper/middlerouter.git
set -e

# Make sure only root can run our script
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

install_packages()
{
    echo -n        $2
    apt-get install -y $1 > /dev/null &
    local pid=$! # Process Id of the previous running command

    spin[0]="-"
    spin[1]="\\"
    spin[2]="|"
    spin[3]="/"

    local spin='-\|/'
    local i=0
    while kill -0 $pid 2>/dev/null
    do
      i=$(( (i+1) %4 ))
      printf "\r${spin:$i:1}"
      sleep .1
    done
    
    ecode=$(wait $pid)
    if [[ $ecode -eq 0 ]]; then
        echo -e "\r[\e[92m OK \e[39m]"
    else
        echo -e "\r[\e[91m ERR \e[39m]"
    fi
}

install_sniffer()
{
    cd "$DEST_DIR"
    pip install -r requirements_sniffer.txt
    
    # Setup runscript for the sniffer
    cp sniffer_srv /etc/init.d/sniffer_srv
    chmod +x /etc/init.d/sniffer_srv
    sudo update-rc.d sniffer_srv defaults
    sudo update-rc.d sniffer_srv enable

    # Create log rotating rule for logging
    cp sniffer_log_rule /etc/logrotate.d/sniffer
}

install_analyzer()
{
    # Install analyzer dependencies
    install_packages "tshark bro" "Installing analyzer dependencies: tshark and BRO"
    install_packages 'cmake make gcc resolvconf g++ flex bison libpcap-dev libssl-dev python-dev swig zlib1g-dev' "Installing analyzer dependencies libs"

    echo "Installing analyzer python dependencies..."
    cd "$DEST_DIR"
    pip install -r requirements_analyzer.txt

    # Setup runscript for the analyzer
    echo "Installing analyzer service"
    cp analyzer_srv /etc/init.d/analyzer_srv
    chmod +x /etc/init.d/analyzer_srv
    sudo update-rc.d analyzer_srv defaults
    sudo update-rc.d analyzer_srv enable

    # Create log rotating rule for logging
    cp analyzer_log_rule /etc/logrotate.d/analyzer
}

# Install dependencies
echo "Verifying dependencies: this might take a while"
apt-get update > /dev/null

install_packages "build-essential logrotate git dnsmasq libffi-dev libssl-dev libxml2-dev libxml2-dev libxslt1-dev ssdeep libffi-dev libfuzzy-dev daemontools tcpdump" "Installing package dependencies"
install_packages "python2.7 python-pip python-dev python2.7-dev" "Installing python environment"

echo "Upgrading pip..."
python -m pip install --upgrade pip

# Download the MiddleRouter python binaries
echo -e " ...  Downloading software into $DEST_DIR"
if [[ -d "$DEST_DIR" ]]; then
    echo "Directory $DEST_DIR already exists. Deleting it."
    rm -R "$DEST_DIR"
else
    mkdir "$DEST_DIR"
fi

git clone "$GIT_REPO" $DEST_DIR
chmod +x $DEST_DIR/start_sniffer.py
chmod +x $DEST_DIR/start_analyzer.py

# Ask the user if she wants to install the sniffer
while true; do
    read -p "Install sniffer agent on this machine? [Y/n]: " RESP
    if [[ "$RESP" = "y" || "$RESP" = "Y" || "$RESP" = "" ]] 
    then
      install_sniffer
      break
    elif [[ "$RESP" = "n" || "$RESP" = "N" ]]
    then
        break
    fi
done

while true; do
    read -p "Install analyzer agent on this machine? [Y/n]: " RESP
    if [[ "$RESP" = "y" || "$RESP" = "Y" || "$RESP" = "" ]] 
    then
      install_analyzer
      break
    elif [[ "$RESP" = "n" || "$RESP" = "N" ]]
    then
        break
    fi
done

echo -e "\e[92m Installation Completed \e[39m"
# We are done!