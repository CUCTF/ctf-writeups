import binascii
from Crypto.Util.number import long_to_bytes
n = 51892897382689572842045070488499783740392464715010639950375414286706759299308737295424729548173258420526568084233544152881325883921776347584183757378688012355765839129549376012208807986255091230676757766254877610974534480806555973484514403710999836102861504718137481576183741889014334248115047806422088665887428610011866916433120265855438477650498984637501192689177967178938635808317718949879261889904926622523146368344817633320077148643333708434915134803046778600470616771269269365439488394491912502144709567029
c = 1128402571314301061197849469387298504411323616860706421398106925690130683396872054810885667844296506565322624205383437420753898248505207364020589572861235048768359548847646177553236617086713073617581990180333904518292952884888429535941258911403810143897897755482177112455671062917783205785395824752114938745320779852361984762039955943080713658881042310566624436487283978991174571463483800989409730533398126074765149708718551981800818873408968765936833756167679088163178302040718335158827510217324640711602186405
e = 65537

def solve():
    # p and q end in 7
    candidates = [(7, 7)]
    
    # We need to find 256 digits
    for i in range(1, 256):
        new_candidates = []
        mod = 10**(i + 1)
        target = n % mod
        
        for p_val, q_val in candidates:
            # Test all combinations of next digits
            for p_digit in [6, 7]:
                for q_digit in [6, 7]:
                    p_next = p_digit * (10**i) + p_val
                    q_next = q_digit * (10**i) + q_val
                    
                    if (p_next * q_next) % mod == target:
                        new_candidates.append((p_next, q_next))
        candidates = new_candidates
        # Optimization: If we have multiple branches, just keep going. 
        # Usually, only 1 or 2 branches survive.
    
    return candidates

all_pairs = solve()
print(f"[+] Found {len(all_pairs)} potential candidate pairs.")

for i, (p_test, q_test) in enumerate(all_pairs):
    # Verification 1: Do they multiply to n?
    if p_test * q_test == n:
        print(f"[!] Verification successful for pair {i}!")
        
        # Verification 2: Are they prime? (Optional but good)
        # from Crypto.Util.number import isPrime
        # if not isPrime(p_test): continue

        phi = (p_test - 1) * (q_test - 1)
        d = pow(e, -1, phi)
        m = pow(c, d, n)
        
        decrypted_bytes = long_to_bytes(m)
        if b"lactf{" in decrypted_bytes:
            print(f"SUCCESS! Flag: {decrypted_bytes.decode()}")
            break
        else:
            print(f"Pair {i} multiplied correctly but resulted in garbage. Still searching...")
