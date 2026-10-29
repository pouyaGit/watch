# Two probes: is the model failing, or are we misreading it?

Both are read-only. Run them before proposing a fix, not after. Together they
separate the three causes that look identical from the outside: the provider
down, the model returning bad content, and a good answer discarded in transit.

## 1. Capture the raw envelope

A semantic failure class (`MISSING_CHOICES`, `MISSING_FIELD`, `EMPTY_RESPONSE`)
is raised in the parse layer. It tells you what the decoder could not find, not
what the model did. Dump the body and read it yourself.

```python
dec = json.JSONDecoder()
env, end = dec.raw_decode(raw)          # decode the FIRST json value
tail = raw[end:].strip()                 # whatever the gateway appended
print("model:", env.get("model"), "finish:", env["choices"][0]["finish_reason"])
print("trailing bytes:", repr(tail[:200]))
inner = json.loads(env["choices"][0]["message"]["content"])
print("inner keys:", sorted(inner))
```

Then get a second, independent opinion on the content:

```python
validate_analysis(inner)   # -> (ok, errors)
```

Discriminate on what you see:

| observation | actual cause | where the fix lives |
|---|---|---|
| `trailing bytes: 'data: [DONE]'`, inner JSON valid, `validate_analysis` ok | gateway appended an SSE terminator to a non-streaming response; strict whole-body `json.loads` raised "Extra data" | the parse layer — strip the terminator before decoding |
| inner object missing required keys | the model's output really is incomplete | the prompt / the stage that demanded the keys |
| `choices` absent or empty | the gateway returned a different envelope entirely | transport / gateway config |

The middle row is the one that gets misreported. "The pipeline reports
MISSING_CHOICES" and "the model returned valid content" are different defects in
different files; do not hand the user the pipeline's own error class as the
cause.

Print the served model name. An alias (`requested_model` vs the model actually
routed) is worth noting in the report — it is a routing detail, not a fault,
but it changes how latency and cost should be reasoned about.

## 2. Time a size ladder, not one big call

When the hypothesis is "the input is too large", the same call at three sizes
kills it or confirms it in one shot:

```
real size -> wall, ok/err
half      -> wall, ok/err
~2x cap   -> wall, ok/err
```

- **Non-monotonic latency** (bigger input faster than smaller) means the time is
  not in the input — it is queueing, routing or model variance. Stop reading
  volume into the number.
- **Identical error at every rung** means the call is always broken, and size is
  not the variable. A single oversized test cannot distinguish "too big" from
  "always broken"; the ladder is what separates them.
- **Read the config defaults too** (timeout, max tokens, input cap) so the
  measured wall times can be compared against the limits that were in force.

Before running any ladder, print the real input-length distribution:

```sql
SELECT MIN(LENGTH(content)), MAX(LENGTH(content)), AVG(LENGTH(content))
FROM <artifact_table>;
```

A configured cap is a limit, not a measurement. If the largest real artifact is
4 KB, the pipeline cannot be context-bound no matter what the cap says — and if
a brief asserts a size the data contradicts, correct it with the numbers instead
of testing the asserted figure.

## 3. Do not fabricate throughput

If the gateway returns an empty `usage` object, tokens-per-second cannot be
computed. Report that the measurement is unavailable and name the missing field.
Never back into a number from wall time and an estimated output length.
