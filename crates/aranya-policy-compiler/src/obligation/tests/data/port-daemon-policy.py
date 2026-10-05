"""Port Aranya's daemon policy to the current policy syntax, as a test
artifact for the obligation analysis. Run from the aranya-core root, with
`aranya-project/aranya` checked out alongside it as `../aranya`.

Each rewrite asserts what it expects to find, so a change upstream that
the port doesn't handle fails loudly instead of producing a wrong port."""
import re
import subprocess

UPSTREAM = '../aranya'
SRC = f'{UPSTREAM}/crates/aranya-daemon/src/policy.md'
DST = 'crates/aranya-policy-compiler/src/obligation/tests/data/daemon-policy.md'

def depth(t):
    d = 0
    for ch in t:
        if ch in '([{':
            d += 1
        elif ch in ')]}':
            d -= 1
    return d

def append_at_end(lines, start, col, terminal):
    """Append `terminal` where the expression starting at (start, col)
    ends: the first line, from `col`, where the brackets balance."""
    d, i = 0, start
    while True:
        d += depth(lines[i][col:] if i == start else lines[i])
        if d == 0:
            assert '//' not in lines[i], ('comment at expression end', i + 1)
            lines[i] = lines[i].rstrip() + ' ' + terminal
            return
        assert d > 0, ('expression does not close cleanly', start + 1)
        i += 1

def policy_lines(lines):
    """Indexes of the lines inside ```policy fences."""
    inside = False
    for i, l in enumerate(lines):
        s = l.strip()
        if s.startswith('```'):
            inside = (s == '```policy') and not inside
            continue
        if inside:
            yield i

def git(*args):
    return subprocess.check_output(['git', '-C', UPSTREAM, *args], text=True).strip()

# The provenance note names the upstream commit, so the policy must be
# exactly as committed there.
assert not git('status', '--porcelain', '--', 'crates/aranya-daemon/src/policy.md'), \
    'the upstream policy has uncommitted changes'
REV = git('rev-parse', '--short=8', 'HEAD')

lines = open(SRC).read().split('\n')
counts = dict(check=0, check_unwrap=0, unwrap=0, seal=0, open=0, headers=0)

# 1. `check_unwrap e` -> `e or test_fail()`. Every use is a whole
#    statement value, so the terminal goes where the expression ends.
for i in list(policy_lines(lines)):
    if 'check_unwrap ' in lines[i]:
        col = lines[i].index('check_unwrap ')
        lines[i] = lines[i][:col] + lines[i][col + len('check_unwrap '):]
        append_at_end(lines, i, col, 'or test_fail()')
        counts['check_unwrap'] += 1

# 2. `unwrap x` -> `(x or test_fail())`. Every operand is a plain name,
#    and the parentheses keep the result right in any position.
for i in list(policy_lines(lines)):
    if lines[i].strip().startswith('//'):
        continue
    for m in reversed(list(re.finditer(r'\bunwrap (\w+)', lines[i]))):
        lines[i] = lines[i][:m.start()] + f'({m.group(1)} or test_fail())' + lines[i][m.end():]
        counts['unwrap'] += 1
    assert not re.search(r'\bunwrap\b', lines[i]), ('unported unwrap', i + 1, lines[i])

# 3. A bare `check c` -> `check c else test_fail()`.
for i in list(policy_lines(lines)):
    m = re.match(r'(\s*)check\s', lines[i])
    if not m:
        continue
    j, d = i, 0
    while True:
        d += depth(lines[j][m.end():] if j == i else lines[j])
        if d == 0:
            break
        j += 1
    if ' else ' not in ' '.join(lines[i:j + 1]):
        append_at_end(lines, i, m.end(), 'else test_fail()')
        counts['check'] += 1

# 4a. The `seal_command` and `open_envelope` helpers served only the
#     `seal` and `open` blocks, and `crypto` only them.
def drop_function(lines, name):
    start = next(i for i, l in enumerate(lines) if l.startswith(f'function {name}('))
    # Take the comment lines directly above it too.
    while start > 0 and lines[start - 1].startswith('//'):
        start -= 1
    end, d = start, 0
    while True:
        d += lines[end].count('{') - lines[end].count('}')
        end += 1
        if d == 0 and '{' in ''.join(lines[start:end]):
            break
    del lines[start:end]
for name in ('seal_command', 'open_envelope'):
    drop_function(lines, name)
    counts['helpers'] = counts.get('helpers', 0) + 1

# 4. `seal`/`open` blocks -> base commands with `get_key`.
out, inside, i, in_create_team = [], False, 0, False
while i < len(lines):
    l, s = lines[i], lines[i].strip()
    if s.startswith('```'):
        inside = (s == '```policy') and not inside
        out.append(l); i += 1; continue
    if inside:
        m = re.match(r'(\s*)((?:ephemeral )?command) (\w+) \{\s*$', l)
        if m:
            base = 'TeamInit' if m.group(3) == 'CreateTeam' else 'Signed'
            in_create_team = m.group(3) == 'CreateTeam'
            out.append(f'{m.group(1)}{m.group(2)} {m.group(3)} with {base} {{')
            counts['headers'] += 1; i += 1; continue
        m = re.match(r'\s*(seal|open) \{', l)
        if m:
            d = 0
            while True:
                d += lines[i].count('{') - lines[i].count('}')
                i += 1
                if d == 0:
                    break
            counts[m.group(1)] += 1
            continue
        if in_create_team and s == 'owner_keys struct PublicKeyBundle,':
            if out and out[-1].strip() == "// The initial owner's public Device Keys.":
                out.pop()
            i += 1; continue
    out.append(l); i += 1
assert not any('crypto::' in l for l in out), 'crypto still used'
out = [l for l in out if l.strip() != 'use crypto']
text = '\n'.join(out)

anchor = "## Devices and Identity\n"
assert text.count(anchor) == 1
text = text.replace(anchor, """## Base Commands

Added by the port: commands now get their verification key from a base
command's `get_key` block instead of `seal` and `open` blocks.

```policy
// `CreateTeam` is the first command in the graph, so its key comes from
// its own fields.
base command TeamInit {
    fields {
        // The initial owner's public Device Keys.
        owner_keys struct PublicKeyBundle,
    }
    get_key {
        return Some(this.owner_keys.sign_key)
    }
}

// Every other command is verified with the author's Device Signing Key.
base command Signed {
    get_key {
        return match query DeviceSignPubKey[device_id: author_id] {
            Some(f) => Some(f.key)
            None => None
        }
    }
}
```

""" + anchor)

# Provenance, after the front matter.
lines = text.split('\n')
assert lines[0] == '---'
end = lines.index('---', 1)
lines[end + 1:end + 1] = [
    '',
    "> **Test artifact.** This is Aranya's daemon policy",
    f'> (`aranya-project/aranya` at `{REV}`, `crates/aranya-daemon/src/policy.md`),',
    '> ported to the current policy syntax so the obligation analysis can be',
    '> measured on a real policy. It is not the production policy. The port is',
    '> mechanical: each bare `check c` became `check c else test_fail()`, each',
    '> `check_unwrap e` became `e or test_fail()`, and each `unwrap x` became',
    '> `(x or test_fail())`. Commands no longer have `seal` and `open` blocks:',
    '> `CreateTeam` uses the `TeamInit` base command, which takes `owner_keys`',
    '> from it, and every other command uses `Signed`, which looks up the',
    "> author's `DeviceSignPubKey`. The `seal_command` and `open_envelope`",
    "> helpers, used only by `seal` and `open`, are gone, and with them",
    "> `use crypto`. Nothing else was changed. `port-daemon-policy.py`, next",
    "> to this file, regenerates it.",
]
open(DST, 'w').write('\n'.join(lines))
print(counts)
