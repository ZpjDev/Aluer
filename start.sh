#!/bin/bash

# Aluer ServerGuard 启动脚本

cd /opt/serverguard

echo "正在启动服务..."
nohup java -jar serverguard.jar > serverguard.log 2>&1 &

PID=$!
echo "服务已启动, PID: $PID"
echo "查看日志: tail -f serverguard.log"
