import pandas as pd, re

df = pd.read_csv('https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonEC2/current/us-east-1/index.csv',
                skiprows=5, low_memory=False)

s = [o for o in df['Instance Type'].unique() if isinstance(o, str) and '.' in o]

def _sortkey(o):
    a,o = o.split('.')
    num,o = re.sub(r'^(\d*)(.*?)$', r'0\1 \2', o).split()
    return a,int(num),o

s = sorted(list(s), key=_sortkey)

with open('insttypes.txt', 'w') as f:
    for o in s: f.write(o+'\n')

prices = df[(df['TermType']=='OnDemand') & (df['PricePerUnit']>0) & (df['Tenancy']=='Shared')
             & pd.isna(df['Pre Installed S/W']) & (df['Operating System']=='Linux')  & (df['CapacityStatus']=='Used')]

prices[['Instance Type', 'PricePerUnit']].to_csv('prices.csv', index=False)

