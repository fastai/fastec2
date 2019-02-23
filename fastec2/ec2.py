import numpy as np, pandas as pd
import boto3, re, time, typing, socket, paramiko, os, pysftp, collections, json, shlex, sys
import inspect, subprocess, shutil
from typing import Callable,List,Dict,Tuple,Union,Optional,Iterable
from pathlib import Path
from dateutil.parser import parse
from pkg_resources import resource_filename
from pdb import set_trace
from .spot import *

__all__ = 'EC2 result results snake2camel make_filter listify'.split()

here = os.path.abspath(os.path.dirname(__file__)) + '/'

def snake2camel(s, split='_'): return ''.join([w.title() for w in s.split(split)])
def _make_dict(d:Dict):   return [{'Key':k, 'Value':  v } for k,v in (d or {}).items()]
def _get_dict(l):
    if l is None: return None
    return collections.defaultdict(str, {o['Key']:o['Value'] for o in l})

def _boto3_name(self):
    d = _get_dict(self.tags)
    return None if d is None else d['Name']
boto3.resources.base.ServiceResource.name = property(_boto3_name)

def _boto3_repr(self):
    clname =  self.__class__.__name__
    if clname == 'ec2.Instance':
        return f'{self.name} ({self.id} {self.instance_type} {self.state["Name"]}): {self.public_ip_address or "No public IP"}'
    elif clname == 'ec2.Volume':
        return f'{self.name} ({self.id} {self.state}): {self.size}GB'
    elif clname == 'ec2.Snapshot':
        return f'{self.name} ({self.id} {self.state}): {self.volume_size}GB'
    elif clname == 'ec2.Image':
        root_dev = [o for o in self.block_device_mappings if self.root_device_name == o['DeviceName']]
        return f'{self.name} ({self.id} {self.state}): {root_dev[0]["Ebs"]["VolumeSize"]}GB'
    else:
        identifiers = [f'{ident}={repr(getattr(self, ident))}' for ident in self.meta.identifiers]
        return f"{self.__class__.__name__}({', '.join(identifiers)})"
boto3.resources.base.ServiceResource.__repr__ = _boto3_repr

_in_notebook = False
try:
    from ipykernel.kernelapp import IPKernelApp
    _in_notebook = IPKernelApp.initialized()
except: pass

def listify(p=None, q=None):
    "Make `p` listy and the same length as `q`."
    if p is None: p=[]
    elif isinstance(p, str):          p=[p]
    elif not isinstance(p, Iterable): p=[p]
    n = q if type(q)==int else len(p) if q is None else len(q)
    if len(p)==1: p = p * n
    assert len(p)==n, f'List len mismatch ({len(p)} vs {n})'
    return list(p)

def make_filter(d:Dict=None):
    if d is None: d={}
    d = {k.replace('_','-'):v for k,v in d.items()}
    return {'Filters': [{'Name':k, 'Values':listify(v)} for k,v in (d or {}).items()]}

def results(r):
    if isinstance(r, typing.List): r = r[0]
    return {o:r[o] for o in r.keys() if o !='ResponseMetadata'}
    if not k: return None
    return r[k[0]]

def result(r):
    if isinstance(r, typing.List): r = r[0]
    k = [o for o in r.keys() if o !='ResponseMetadata']
    if not k: return None
    return r[k[0]]

def _get_regions():
    endpoint_file = resource_filename('botocore', 'data/endpoints.json')
    with open(endpoint_file, 'r') as f: a = json.load(f)
    return {k:v['description'] for k,v in a['partitions'][0]['regions'].items()}

def _get_insttypes():
    "Dict of instance types (eg 'p3.8xlarge') for each instance category (eg 'p3')"
    s = [o.strip() for o in open(here+'insttypes.txt').readlines()]
    d = collections.defaultdict(list)
    for l in s: d[l[:2]].append(l.strip())
    return d


class EC2():
    def __init__(self, region:str=None):
        self.curr_region = ''
        if region:
            self.curr_region = self.region(region)
            boto3.setup_default_session(region_name=self.curr_region)
        self._ec2 = boto3.client('ec2')
        self._ec2r = boto3.resource('ec2')
        self.insttypes = _get_insttypes()

    def _resources(self, coll_name, owned=None, **filters):
        coll = getattr(self._ec2r,coll_name)
        filt = make_filter(filters)
        if owned: filt['OwnerIds']=['self']
        return coll.filter(**filt)

    def print_resources(self, coll_name, owned=None, **filters):
        for o in self._resources(coll_name, owned=owned, **filters): print(o)

    def resource(self, coll_name, **filters):
        "The first resource from collection `coll_name` matching `filters`"
        try: return next(iter(self._resources(coll_name, **filters)))
        except StopIteration: raise KeyError(f'Resource not found: {coll_name}; {filters}') from None

    def region(self, region:str):
        "Get first region containing substring `region`"
        regions = _get_regions()
        if region in regions: return region
        return next(r for r,n in regions.items() if region in n)

    def _describe(self, f:str, d:Dict=None, **kwargs):
        "Calls `describe_{f}` with filter `d` and `kwargs`"
        return result(getattr(self._ec2, 'describe_'+f)(**make_filter(d), **kwargs))

    def instances(self):
        "Print all non-terminated instances"
        states = ['pending', 'running', 'stopping', 'stopped']
        for o in (self._resources('instances', instance_state_name=states)): print(o)

    def _price_hist(self, insttype):
        types = self.insttypes[insttype]
        prices = self._ec2.describe_spot_price_history(InstanceTypes=types, ProductDescriptions=["Linux/UNIX"])
        df = pd.DataFrame(prices['SpotPriceHistory'])
        df["SpotPrice"] = df.SpotPrice.astype(float)
        return df.pivot_table(values='SpotPrice', index='Timestamp', columns='InstanceType', aggfunc='min'
                             ).resample('1D').min().reindex(columns=types).tail(50)

    def price_hist(self, insttype):
        pv = self._price_hist(insttype)
        res = pv.tail(3).T
        if _in_notebook:
            pv.plot()
            return res
        print(res)

    def price_demand(self, insttype):
        "On demand prices for `insttype` (currently only shows us-east-1 prices)"
        prices = dict(pd.read_csv(here+'prices.csv').values)
        return [(o,round(prices[o],3)) for o in self.insttypes[insttype]]

    def waitfor(self, resource, event, ident, timeout=180):
        waiter = self._ec2.get_waiter(f'{resource}_{event}')
        waiter.config.max_attempts = timeout//15
        filt = {f'{snake2camel(resource)}Ids': [ident]}
        waiter.wait(**filt)
        time.sleep(5)

    def get_secgroup(self, secgroupname):
        "Get security group from `secgroupname`, creating it if needed (with just port 22 ingress)"
        try: secgroup = self.resource('security_groups', group_name=secgroupname)
        except KeyError:
            vpc = self.resource('vpcs', isDefault='true')
            secgroup = self._ec2r.create_security_group(GroupName=secgroupname, Description=secgroupname, VpcId=vpc.id)
            secgroup.authorize_ingress(IpPermissions=[{
                'IpRanges': [{'CidrIp': '0.0.0.0/0'}], 'FromPort': 22, 'ToPort': 22,
                'IpProtocol': 'tcp'}] )
        return secgroup

    def get_amis(self, description=None, owner=None, filt_func=None):
        """Return all AMIs with `owner` (or private AMIs if None), optionally matching `description` and `filt_func`.
        Sorted by `creation_date` descending"""
        if filt_func is None: filt_func=lambda o:True
        filt = dict(architecture='x86_64', virtualization_type='hvm', state='available', root_device_type='ebs')
        if owner is None: filt['is_public'] = 'false'
        else:             filt['owner-id'] = owner
        if description is not None: filt['description'] = description
        amis = self._resources('images', **filt)
        amis = [o for o in amis if filt_func(o)]
        if owner is None: amis = [o for o in amis if o.product_codes is None]
        return sorted(amis, key=lambda o: parse(o.creation_date), reverse=True)

    def amis(self, description=None, owner=None, filt_func=None):
        """Return all AMIs with `owner` (or private AMIs if None), optionally matching `description` and `filt_func`.
        Sorted by `creation_date` descending"""
        for ami in self.get_amis(description, owner, filt_func): print(ami)

    def get_ami(self, ami=None):
        "Look up `ami` if provided, otherwise find latest Ubuntu 18.04 image"
        if ami is None:
            amis = self.get_amis('Canonical, Ubuntu, 18.04 LTS*',owner='099720109477',
                                  filt_func=lambda o: not re.search(r'UNSUPPORTED|minimal', o.description))
            assert amis, 'AMI not found'
            return amis[0]

        if ami.__class__.__name__ == f'ec2.Image': return ami
        # If passed a valid AMI id, just return it
        try: return self.resource('images', image_id=ami)
        except KeyError: pass
        if ami: return self.resource('images', name=ami, is_public='false')

    def ami(self, aminame=None): print(self.get_ami(aminame))

    def create_volume(self, ssh, size=None, name=None, snapshot=None):
        inst = ssh.inst
        if name is None: name=inst.name
        if snapshot is None:
            if size is None: raise Exception('Must pass snapshot or size')
        else:
            snapshot = self.get_snapshot(snapshot)
            if size is None: size = snapshot.volume_size
        az = inst.placement['AvailabilityZone']
        xtra = {'SnapshotId':snapshot.id} if snapshot else {}
        vol = self._ec2r.create_volume(AvailabilityZone=az, Size=size, **xtra)
        self.create_name(vol.id, name)
        self.waitfor('volume','available', vol.id)
        self.attach_volume(inst, vol)
        if snapshot is None: ssh.setup_vol(vol)
        else: ssh.mount(vol)
        return vol

    def create_snapshot(self, vol, name=None, wait=False):
        if name is None: name=vol.name
        snap = vol.create_snapshot()
        self.create_name(snap.id, name)
        if wait: self.waitfor('snapshot', 'completed', snap.id)
        return snap

    def _get_resource(self, o, cname, pref):
        if o.__class__.__name__ == f'ec2.{cname}': return o
        coll_name = f'{cname.lower()}s'
        if o.startswith(f'{pref}-'):
            return self.resource(coll_name, **{f'{cname.lower()}_id': o})
        return self.resource(coll_name, **{'tag:Name':o})

    def get_snapshot(self, snap): return self._get_resource(snap, 'Snapshot', 'snap')
    def get_volume(self, vol): return self._get_resource(vol, 'Volume', 'vol')
    def get_instance(self, inst): return self._get_resource(inst, 'Instance', 'i')
    def get_request(self, srid): return SpotRequest.get(self, srid)
    def get_request_from_instance(self, inst): return SpotRequest.from_instance(e, inst)
    def get_requests(self):
        return [SpotRequest(self, o) for o in
                self._describe('spot_instance_requests', {'state':['open','active']})]
    def requests(self):
        for o in self.get_requests(): print(o)

    def mount_volume(self, ssh, vol):
        vol = self.get_volume(vol)
        inst = ssh.inst
        self.attach_volume(inst, vol)
        ssh.mount(vol)

    def attach_volume(self, inst, vol):
        inst = self.get_instance(inst)
        vol.attach_to_instance(Device='/dev/sdh',InstanceId=inst.id)
        self.waitfor('volume', 'in_use', vol.id)

    def detach_volume(self, vol, wait=True):
        vol.detach_from_instance()
        if wait: self.waitfor('volume', 'available', vol.id)

    def change_type(self, inst, insttype):
        inst = self.get_instance(inst)
        inst.modify_attribute(Attribute='instanceType', Value=insttype)

    def freeze(self, inst, name=None):
        inst = self.get_instance(inst)
        if name is None: name=inst.name
        amiid = self._ec2.create_image(InstanceId=inst.id, Name=name)['ImageId']
        return self.get_ami(amiid)

    def _launch_spec(self, ami, keyname, disksize, instancetype, secgroupid, iops=None):
        assert self._describe('key_pairs', {'key-name':keyname}), 'default key not found'
        ami = self.get_ami(ami)
        ebs = ({'VolumeSize': disksize, 'VolumeType': 'io1', 'Iops': 6000 }
                 if iops else {'VolumeSize': disksize, 'VolumeType': 'gp2'})
        return { 'ImageId': ami.id, 'InstanceType': instancetype,
            'SecurityGroupIds': [secgroupid], 'KeyName': keyname,
            "BlockDeviceMappings": [{ "DeviceName": "/dev/sda1", "Ebs": ebs, }] }

    def _get_request(self, srid):
        srs = self._describe('spot_instance_requests', {'spot-instance-request-id':srid})
        if not srs: return None
        return srs[0]

    def create_tag(self, resource_id, key, val):
        self._ec2.create_tags(Resources=[resource_id], Tags=_make_dict({key: val}))

    def create_name(self, resource_id, name):
        self.create_tag(resource_id, 'Name', name)

    def remove_name(self, resource_id):
        self._ec2.delete_tags(Resources=resource_id,Tags=[{"Key": 'Name'}])

    def request_spot(self, name, ami, keyname, disksize, instancetype, secgroupid, iops=None):
        spec = self._launch_spec(ami, keyname, disksize, instancetype, secgroupid, iops)
        sr = result(self._ec2.request_spot_instances(
            LaunchSpecification=spec, InstanceInterruptionBehavior='stop', Type='persistent'))
        assert len(sr)==1, 'spot request failed'
        srid = sr[0]['SpotInstanceRequestId']
        try: self.waitfor('spot_instance_request', 'fulfilled', srid)
        except: raise Exception(self._get_request(srid)['Fault']['Message']) from None
        sr = SpotRequest.get(self, srid)
        self.create_name(sr.id, name)
        return sr

    def request_demand(self, ami, keyname, disksize, instancetype, secgroupid, iops=None):
        spec = self._launch_spec(ami, keyname, disksize, instancetype, secgroupid, iops)
        return self._ec2r.create_instances(MinCount=1, MaxCount=1, **spec)[0]

    def _wait_ssh(self, inst):
        self.waitfor('instance', 'running', inst.id)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            for i in range(720//5):
                try:
                    s.connect((inst.public_ip_address, 22))
                    time.sleep(1)
                    return inst
                except (ConnectionRefusedError,BlockingIOError): time.sleep(5)

    def get_launch(self, name, ami, disksize, instancetype, keyname:str='default', secgroupname:str='ssh',
                   iops:int=None, spot:bool=False):
        "Creates new instance `name` and returns `Instance` object"
        insts = self._describe('instances', {'tag:Name':name})
        assert not insts, 'name already exists'
        secgroupid = self.get_secgroup(secgroupname).id
        if spot:
            sr = self.request_spot  (name, ami, keyname, disksize, instancetype, secgroupid, iops)
            inst = self._ec2r.Instance(sr.instance_id)
        else   : inst = self.request_demand(ami, keyname, disksize, instancetype, secgroupid, iops)
        self.create_name(inst.id, name)
        return self._wait_ssh(inst)

    def ip(self, inst): return self.get_instance(inst).public_ip_address

    def launch(self, name, ami, disksize, instancetype, keyname:str='default',
               secgroupname:str='ssh', iops:int=None, spot:bool=False):
        print(self.get_launch(name, ami, disksize, instancetype, keyname, secgroupname, iops, spot))

    def instance(self, inst:str):
        "Show `Instance` details for `inst`"
        print(self.get_instance(inst))

    def start(self, inst, show=True):
        "Starts instance `inst`"
        inst = self.get_instance(inst)
        inst.start()
        self._wait_ssh(inst)
        if show: print(inst)
        else: return inst

    def terminate(self, inst):
        "Starts instance `inst`"
        inst = self.get_instance(inst)
        sr = SpotRequest.from_instance(self, inst)
        if sr is not None: sr.cancel()
        inst.terminate()
        self.remove_name(inst.id)

    def stop(self, inst):
        "Stops instance `inst`"
        self.get_instance(inst).stop()

    def connect(self, inst, ports=None, user=None):
        """Replace python process with an ssh process connected to instance `inst`;
        use `user@name` otherwise defaults to user 'ubuntu'. `ports` (int or list) creates tunnels"""
        if user is None:
            if isinstance(inst,str) and '@' in inst: user,inst = inst.split('@')
            else: user = 'ubuntu'
        inst = self.get_instance(inst)
        tunnel = []
        if ports is not None: tunnel = [f'-L {o}:localhost:{o}' for o in listify(ports)]
        os.execvp('ssh', ['ssh', f'{user}@{inst.public_ip_address}', *tunnel])

    def sshs(self, inst, user='ubuntu', keyfile='~/.ssh/id_rsa'):
        inst = self.get_instance(inst)
        ssh = self.ssh(inst, user=user, keyfile=keyfile)
        ftp = pysftp.Connection(ssh)
        return inst,ssh,ftp

    def ssh(self, inst, user='ubuntu', keyfile='~/.ssh/id_rsa'):
        "Return a paramiko ssh connection objected connected to instance `inst`"
        inst = self.get_instance(inst)
        keyfile = os.path.expanduser(keyfile)
        key = paramiko.RSAKey.from_private_key_file(keyfile)
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=inst.public_ip_address, username=user, pkey=key)
        client.raise_stderr = True
        client.inst = inst
        client.launch_tmux()
        return client

    def script(self, scriptname, inst, myip=None, user='ubuntu', keyfile='~/.ssh/id_rsa'):
        inst = self.get_instance(inst)
        name = inst.name
        conf_fn = 'sync.conf'
        if myip is None:
            myip = subprocess.check_output(['curl', '-s', 'http://169.254.169.254/latest/meta-data/public-ipv4']).decode().strip()

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

        fpath = Path.home()/'fastec2'
        path  = fpath/name
        path.mkdir(parents=True, exist_ok=True)
        shutil.copy(scriptname, path)

        ssh = self.ssh(inst, user, keyfile)
        ssh.send('mkdir -p ~/fastec2')
        ssh.send(f'echo {name} > ~/fastec2/current')
        ssh.send(f'ssh-keyscan {myip} >> ~/.ssh/known_hosts')
        ip = inst.public_ip_address
        os.system(f"rsync -e 'ssh -o StrictHostKeyChecking=no' -az {path} {user}@{ip}:fastec2/")
        ssh.send(f'cd {path}')
        ssh.write(f'{fpath}/{conf_fn}', sync_tmpl.format(name=name, ip=myip))
        ssh.send(f'lsyncd ../{conf_fn} -pidfile /tmp/lsyncd.pid')
        ssh.send(f'chmod u+x {scriptname}')
        ssh.send(f'export FE2_DIR={path}')
        ssh.send('./'+scriptname)

def _run_ssh(ssh, cmd, pty=False):
    stdin, stdout, stderr = ssh.exec_command(cmd, get_pty=pty)
    stdout_str = stdout.read().decode()
    stderr_str = stderr.read().decode()
    if stdout.channel.recv_exit_status() != 0: raise Exception(stderr_str)
    if ssh.raise_stderr:
        if stderr_str: raise Exception(stderr_str)
        return stdout_str
    return stdout_str,stderr_str

def _check_ssh(ssh): assert ssh.run('echo hi')[0] == 'hi\n'

def _write_ssh(ssh, fn, s): ssh.open_sftp().open(fn, 'w').write(s)

def _volid_to_dev(ssh, vol):
    volid = vol.id.split('-')[1]
    res = ssh.run(f'readlink -f /dev/disk/by-id/nvme-Amazon_Elastic_Block_Store_vol{volid}').strip()
    assert '/dev/disk/by-id/' not in res, 'Failed to find volume link; is it attached?'
    return res

def _setup_vol(ssh, vol):
    dev = _volid_to_dev(ssh, vol)
    cmds = [
        f'sudo mkfs -q -t ext4 {dev}',
        f'sudo mkdir -p /mnt/fe2_disk',
        f'sudo mount {dev} /mnt/fe2_disk',
        f'sudo chown -R ubuntu /mnt/fe2_disk',
    ]
    for c in cmds: ssh.run(c)
    ssh.write('/mnt/fe2_disk/chk', 'ok')

def _mount(ssh, vol):
    dev = _volid_to_dev(ssh, vol)
    ssh.run(f'sudo mount {dev} /mnt/fe2_disk')

def _umount(ssh): ssh.run('sudo umount /mnt/fe2_disk')

def _launch_tmux(ssh, name=None):
    if name is None: name=ssh.inst.name
    try:
        r = ssh.run(f'tmux ls | grep {name}')
        if r: return ssh
    except: pass
    ssh.run(f'tmux new -s {name} -n {name} -d', pty=True)
    return ssh

def _send_tmux(ssh, cmd, name=None):
    if name is None: name=ssh.inst.name
    ssh.run(f'tmux send-keys -t {name} -l {shlex.quote(cmd)}')
    ssh.run(f'tmux send-keys Enter')

def _ssh_runscript(ssh, script):
    ssh.write('/tmp/tmp.sh', script)
    ssh.run('chmod u+x /tmp/tmp.sh')
    res = ssh.run('/tmp/tmp.sh')
    ssh.run('rm /tmp/tmp.sh')
    return res

paramiko.SSHClient.run = _run_ssh
paramiko.SSHClient.check = _check_ssh
paramiko.SSHClient.send = _send_tmux
paramiko.SSHClient.write = _write_ssh
paramiko.SSHClient.launch_tmux = _launch_tmux
paramiko.SSHClient.mount = _mount
paramiko.SSHClient.umount = _umount
paramiko.SSHClient.setup_vol = _setup_vol
paramiko.SSHClient.runscript = _ssh_runscript

def _pysftp_init(self, ssh):
    self._sftp_live = True
    self._transport = ssh.get_transport()
    self._sftp = paramiko.SFTPClient.from_transport(self._transport)

def _put_dir(sftp, fr, to):
    sftp.makedirs(to)
    sftp.put_d(os.path.expanduser(fr), to)

def _put_key(sftp, name):
    sftp.put(os.path.expanduser(f'~/.ssh/{name}'), f'.ssh/{name}')
    sftp.chmod(f'.ssh/{name}', 600)

pysftp.Connection.__init__ = _pysftp_init
pysftp.Connection.put_dir = _put_dir
pysftp.Connection.put_key = _put_key

def interact(region=''):
    os.execvp('ipython', ['ipython', '--autocall=2', '-ic',
                          f'import fastec2; e=fastec2.EC2("{region}")'])

