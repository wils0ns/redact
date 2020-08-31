# Redact

JSON and text redactor.

## Blackout secrets in a text

Code:

```go
s = NewSecret(`[0-9]{3}\.[0-9]{3}\.[0-9]{3}-[0-9]{2}`, BlackOut, []byte("█"))
```

Original text:

```text
These are a couple of CPFs: 321.654.987-00 and 789.456.123-00
```

Redacted text:

```text
These are a couple of CPFs: ██████████████ and ██████████████
```

## Blackout secret values and omit secret fields from JSON

Code:

```go
bo := []byte("█")
inq := New()
inq.AddSecretValue(NewSecret("secret[s]?", BlackOut, bo))
inq.AddSecretValue(NewSecret("SSN", BlackOut, []byte("")))
inq.AddSecretValue(NewSecret(`[1-9]{3}-[1-9]{2}-[1-9]{4}`, BlackOut, bo))

inq.AddSecretField("date")
inq.AddSecretField("^SSN$")
```

Original JSON:

```json
{
  "Name":"Wilson",
  "create_date": "2020-08-31 15:51:14+00:00",
  "modify_date": "2020-08-31 15:52:15+00:00",
  "SSN": "123-45-6789",
  "quote": "We all have secrets"
}
```

Redacted JSON:

```json
{
  "Name":"Wilson",
  "quote":"We all have ███████"
}
```


Check out the full [code examples](example_test.go).
