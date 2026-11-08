import sys, os, json, tempfile, importlib
sys.path.insert(0, "/home/claude/siemless/tests")
os.environ["HERMES_HOME"] = tempfile.mkdtemp()
from conftest import load_plugin_package
pl = load_plugin_package()
C = pl.__name__ + ".siemless_core"
R = importlib.import_module(C + ".redact")
col = importlib.import_module(C + ".collectors")
ocsf = importlib.import_module(C + ".ocsf")
S = importlib.import_module(C + ".sensitive")

def show(label, v): print(f"--- {label}:", v)
# 1. PEM > 1600 chars in tool arg
pem = "-----BEGIN RSA PRIVATE KEY-----\n" + "\n".join(["MIIEowIBAAKCAQEA" + "Q"*48]*27) + "\n-----END RSA PRIVATE KEY-----"
show("pem len", len(pem))
evs = col.collect("post_tool_call", {"tool_name":"write_file","args":{"path":"/tmp/k","content":pem},"session_id":"s"})
show("pem in args", json.dumps(evs[0].attrs["args"])[:300])
# 2. dict keys with secrets
evs = col.collect("post_tool_call", {"tool_name":"x","args":{"ghp_"+"A"*36: 1, "data":{"sk-ant-"+"B"*40:"v"}},"session_id":"s"})
show("secret keys", json.dumps(evs[0].attrs))
evs = col.collect("post_tool_call", {"tool_name":"x","args":{"ghp_"+"A"*36: 1}},config={"record_args":False})
show("arg_names", evs[0].attrs)
# 3. unlisted secret shapes
for s in ["AWS secret wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "Stripe rk_live_"+"a"*24, "pk_live_x sk_live_" + "c"*24,
          "glsa_"+"d"*32, "dop_v1_"+"e"*64, "SG."+"f"*22+"."+"g"*43, "xoxe.xoxp-1-"+"h"*40, "AccountKey="+"i"*86+"==",
          "mongodb+srv://user:pw@h", "https://user@h/?X-Goog-Signature=abc", "lin_api_"+"j"*40, "hooks.slack.com/services/T000/B000/"+"k"*24,
          "https://discord.com/api/webhooks/123456789012345678/" + "l"*68, "--password hunter2secret", "-p'hunter2secret'", "mysql -uroot -phunter2secret",
          "Authorization: Bearer abc", "PASSWORD: \"hunter2 with space\"", "export OPENAI_API_KEY=sk-proj-"+"m"*40, "AKIA"+"N"*16, "ASIA"+"O"*16,
          '{"password": "hunter2secret"}', "token%3Dabcdefghijklmnop", "api_key=%22abcdefghijkl", "ghp_"+"P"*10, "ｇｈｐ_"+"Q"*36,
          "gh​p_"+"R"*36, "sk-ant-api03-"+"S"*20, "https://api.telegram.org/bot123456789:"+"T"*35+"/send", "?code=4/0Adeu5BW", "SECRET_KEY = 'django-insecure-abc'",
          "private_key_id: abc", '"private_key": "-----BEGIN PRIVATE KEY-----\\nMIIEv', "age-secret-key-1"+"u"*58, "AGE-SECRET-KEY-1"+"U"*58]:
    print(repr(s[:60]), "=>", repr(R.redact_text(s)[:90]))
# 4. whitespace collapse brings truncated tail into preview
s = "x" + " "*1595 + "sk-ant-api03-" + "Z"*40
show("ws tail", R.preview(s, 200))
# 5. list budget not bounded
big = {"a": [[["y"*199]*32]*32]}
out = R.bound_args(big, per_value=200, total=1500)
show("list bound size", len(json.dumps(out)))
