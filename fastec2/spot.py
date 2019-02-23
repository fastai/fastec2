from . import ec2
from .ec2 import *

class SpotRequest():
    def __init__(self, e, d):
        self.e,self.d = e,d
        self._load()

    @classmethod
    def get(cls, e, srid):
        d = e._get_request(srid)
        if d is None: return None
        return cls(e, d)

    @classmethod
    def from_instance(cls, e, inst):
        inst = e.get_instance(inst)
        d = e._describe('spot_instance_requests',{'instance-id':inst.id})
        if d is None: return None
        return cls(e, d[0])

    def load(self):
        if self.d is None: return
        self.d = e._get_request(self.d['SpotInstanceRequestId'])
        self._load()

    def _load(self):
        for s in '''spot_instance_request_id create_time instance_id instance_interruption_behavior
            launched_availability_zone spot_price state status tags type launch_specification'''.split():
            setattr(self, s, self.d[ec2.snake2camel(s)])
        self.id = self.spot_instance_request_id

    def __repr__(self):
        return f'{self.name} ({self.id} {self.state}): {self.instance_type}'

    def cancel(self):
        res = ec2.result(self.e._ec2.cancel_spot_instance_requests(SpotInstanceRequestIds=[self.id]))
        self.e.remove_name(self.name)

    @property
    def instance_type(self): return self.launch_specification['InstanceType']

    @property
    def name(self): return ec2._boto3_name(self)

