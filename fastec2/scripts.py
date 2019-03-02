sync_tmpl = """settings {{
   logfile    = "/tmp/lsyncd.log",
   statusFile = "/tmp/lsyncd.status",
}}
sync {{
   default.rsync,
   delete = false,
   source = "/home/{user}/fastec2/{name}/",
   target = "{ip}:fastec2/{name}"
}}"""

lsync_cfg = """[Unit]
Description=lsyncd
After=network.target

[Service]
Type=simple
Restart=on-failure
RestartSec=3
User={user}
ExecStart=/usr/bin/lsyncd -nodaemon -pidfile /tmp/lsyncd.pid /home/{user}/fastec2/sync.conf
ExecReload=/bin/kill -HUP $MAINPID
PIDFile=/tmp/lsyncd.pid

[Install]
WantedBy=multi-user.target
"""

script_svc_tmpl = """[Unit]
Description={script}
After=network.target

[Service]
Type=simple
User={user}
ExecStart={path}/{script} |& tee -a /home/{user}/fastec2/{name}/{script}.log

[Install]
WantedBy=multi-user.target
"""


script_tmpl = """#!/usr/bin/env bash

source ~/anaconda3/etc/profile.d/conda.sh
conda activate
python {path}/{script}.py
"""

