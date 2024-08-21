import random
random.seed(42)
asns = ['AS1', 'AS2', 'AS3', 'AS4']
def random_asn(candidates: list) -> str:
    """
    >>> random.seed(42)
    >>> random_asn(['AS1', 'AS2', 'AS3'])
    'AS2'
    """
    
    return random.choice(candidates)        

def get_random_asn(unused) -> str:
    """
    >>> random.seed(42)
    >>> random_asn(['AS1', 'AS2', 'AS3'])
    'AS2'
    """
    
    return random_asn(asns) 