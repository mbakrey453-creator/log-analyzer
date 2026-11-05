# Intrusion Detection Log Analyzer

Web GUI course project for Data Structures. Four student-implemented ADTs process mixed authentication logs and simulate IP blocks when a source IP has too many failed authentications inside a circular window of the last **N** events.

Python 3 standard library only. No `pip` packages. `collections.deque` is **not** used as a required structure.

## How to run

From this folder:

```text
python main.py
```

This starts the built-in server and opens the web GUI (HTML/CSS/JS) at `http://127.0.0.1:8765`. Use `python main.py 9000` for a custom port. The classic tkinter GUI is still available via `python gui.py`.

On Windows, `py main.py` also works if the `python` command is not on PATH.

## Demo (about two minutes)

1. Leave **Window size N = 50** and **Fail threshold = 5**.
2. Set **Virtual attempts** to 50 (slider or number field) in the **Data Source** card.
3. Click **Generate Virtual Attacks** — fake SSH/Apache/firewall lines go into the FIFO Queue (and the on-screen feed). A brute-force burst from `192.0.2.44` is included.
4. Click **Process Queue** — dequeue → parse → Linked List history → circular window → maybe **simulated BLOCK**.
5. Use the **Inspection** card: **Show History**, **Show Last N**, **Show Blocked IPs**.
6. Click **Undo Last Block** — Stack pop unblocks the IP; history is **not** rewritten.
7. Optional: **Load Log File** and pick `samples/auth_mixed.log` or `samples/brute_force.log`. **Auto-generate Burst** injects extra failures from the Burst IP field.

## Data structures

| ADT | Module | Role |
|-----|--------|------|
| Queue (linked, head+tail) | `ds/queue.py` | Raw log lines FIFO until Process |
| Singly Linked List + tail | `ds/linked_list.py` | Full chronological event history |
| Stack | `ds/stack.py` | Simulated IP blocks for LIFO undo |
| Circular Array of size N | `ds/circular_buffer.py` | Last N events for brute-force detection |

Detection rule: count failed authentications per source IP inside the circular window; if count ≥ threshold and the IP is not already blocked, push a simulated block onto the Stack.

Blocks do **not** change a real firewall.

## Layout

- `main.py` — launches the web server and opens the browser
- `server.py` — stdlib HTTP server + JSON API for the web GUI
- `web/` — the web GUI (`index.html`, `style.css`, `app.js`)
- `gui.py` — classic tkinter GUI (fallback)
- `engine.py` — wires ADTs + parser + detector
- `parser.py` — SSH / Apache / firewall-ish lines → `Event`
- `detector.py` — window scan and block decision
- `simulator.py` — virtual login-attempt producer
- `ds/` — the four ADTs
- `samples/` — starter `.log` files
