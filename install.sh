#!/bin/bash

# Aluer ServerGuard 一键安装脚本

echo "========================================="
echo "  Aluer ServerGuard 一键部署"
echo "========================================="

# 检查root权限
if [ "$EUID" -ne 0 ]; then 
   echo "请使用 sudo 运行此脚本"
   exit 1
fi

# 1. 安装Java
echo "[1/5] 正在安装 Java 17..."
if command -v java &> /dev/null; then
    echo "Java已安装: $(java -version 2>&1 | head -1)"
else
    apt update && apt install openjdk-17-jdk -y
    echo "Java 安装完成"
fi

# 2. 创建工作目录
echo "[2/5] 创建工作目录..."
mkdir -p /opt/serverguard
cd /opt/serverguard
echo "工作目录: /opt/serverguard"

# 3. 提示上传jar
echo "[3/5] 上传 jar 包..."
echo "请将 serverguard.jar 上传到 /opt/serverguard/"
echo "上传命令: scp serverguard.jar user@你的服务器IP:/opt/serverguard/"
echo ""

# 等待jar文件
while [ ! -f serverguard.jar ]; do
    echo "等待上传 jar 包... (按 Ctrl+C 退出)"
    sleep 5
done
echo "jar 包已就绪"

# 4. 配置systemd服务
echo "[4/5] 配置系统服务..."
cat > /etc/systemd/system/serverguard.service << 'EOF'
[Unit]
Description=Aluer ServerGuard
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/serverguard
ExecStart=/usr/bin/java -jar /opt/serverguard/serverguard.jar
ExecStop=/bin/kill -15 $MAINPID
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable serverguard

# 5. 启动服务
echo "[5/5] 启动服务..."
systemctl start serverguard
sleep 3

# 检查状态
if systemctl is-active --quiet serverguard; then
    echo ""
    echo "========================================="
    echo "  ✓ 部署成功!"
    echo "========================================="
    echo ""
    echo "访问地址: http://你的服务器IP:8080"
    echo "API测试:  curl http://localhost:8080/api/status"
    echo ""
    echo "管理命令:"
    echo "  查看状态: systemctl status serverguard"
    echo "  查看日志: journalctl -u serverguard -f"
    echo "  重启服务: systemctl restart serverguard"
    echo "  停止服务: systemctl stop serverguard"
else
    echo ""
    echo "部署失败，请查看日志:"
    echo "  journalctl -u serverguard"
fi
