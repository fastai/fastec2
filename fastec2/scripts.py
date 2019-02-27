
sync_tmpl = """
settings {{
   logfile    = "/tmp/lsyncd.log",
   statusFile = "/tmp/lsyncd.status",
}}
sync {{
   default.rsync,
   delete = false,
   source = ".",
   target = "{ip}:fastec2/{name}"
}}"""


lsync_cfg = """
[Unit]
Description=lsyncd
After=network.target

[Service]
Type=simple
Restart=on-failure
RestartSec=3
User=ubuntu
ExecStart=/usr/bin/lsyncd -nodaemon -pidfile /tmp/lsyncd.pid /home/ubuntu/fastec2/sync.conf
ExecReload=/bin/kill -HUP $MAINPID
PIDFile=/tmp/lsyncd.pid

[Install]
WantedBy=multi-user.target
"""

