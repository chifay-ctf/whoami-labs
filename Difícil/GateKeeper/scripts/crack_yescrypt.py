#!/usr/bin/env python3
import subprocess, sys

def mkhash(password, salt_prefix):
    p = subprocess.run(['mkpasswd','-m','yescrypt','-S',salt_prefix],
                       input=password, capture_output=True, text=True)
    return p.stdout.strip()

targets = {
 'mauricio': '$y$j9T$LzRi8wg.M.qc29RazBixR0$zheAqWCenGJQqPz7.YhuXXVfV3wMPC7B.53UNMXw9a/',
 'developer': '$y$j9T$61HLWdts3L1MeKlM4K2Dh1$mVFybjeDXi6ESCXpC8sQTZ60La4CY8m6S5vfp44EGXD',
}

def verify(password):
    for user, full in targets.items():
        prefix = '$'.join(full.split('$')[:4])  # $y$j9T$params$salt ->
        generated = mkhash(password, prefix)
        if generated == full:
            return user
    return None

if __name__=='__main__':
    wordlist = sys.argv[1]
    with open(wordlist, errors='ignore') as f:
        for i, line in enumerate(f):
            pw = line.strip()
            if not pw: continue
            r = verify(pw)
            if r:
                print(f"*** CRACKED [{r}]: {pw}")
                sys.exit(0)
            if i % 200 == 0:
                print(f"...{i} probadas", file=sys.stderr)
    print("no crakeado en wordlist")
