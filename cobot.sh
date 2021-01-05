#!/bin/bash
origin_pwd=$(pwd)
cobot_path=$(pwd)/cobot
mongod_path=$(pwd)/cobot/mongodblinux
echo $origin_pwd
echo $cobot_path $mongod_path
function check_mongod() {
    netstat -a | grep 27017
    if [ $? -ne 0 ]; then
        cd $mongod_path
        ./sh
    fi
}

check_mongod
cd $origin_pwd
echo $pwd
echo "java -jar cobot/binary.jar -p="$1""
java -jar cobot/binary.jar -p="$1"
#java -jar cobot/source.jar -p="$1"
