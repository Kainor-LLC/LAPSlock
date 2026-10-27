# Slices the debug perf log (-LAPSlockPerfLog, category "perf") by the phases of a scripted run.
# phases.txt: one line per phase, "YYYY-MM-DD HH:MM:SS name", then a line starting END.
# log: xcrun simctl spawn <device> log show --start ... --end ... --predicate 'subsystem == "com.kainor.lapslock" AND category == "perf"' --style compact
# python3 -I scripts/perf/perf_phases.py phases.txt perf.log
import sys, re, collections, datetime

phases_path, log_path = sys.argv[1], sys.argv[2]
marks = []
for line in open(phases_path):
    line = line.strip()
    if not line:
        continue
    if line.startswith("END"):
        parts = line.split(" ", 1)
        stamp = line[4:].strip() if len(line) > 4 else ""
        marks.append((None, "END", line))
        continue
    when = datetime.datetime.strptime(line[:19], "%Y-%m-%d %H:%M:%S")
    marks.append((when, line[20:].strip(), line))
# END line may hold a time after "END " or before it
end_time = None
for when, name, raw in marks:
    if name == "END":
        m = re.search(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", raw)
        if m:
            end_time = datetime.datetime.strptime(m.group(0), "%Y-%m-%d %H:%M:%S")
starts = [(w, n) for w, n, _ in marks if w is not None]
if end_time is None:
    end_time = starts[-1][0] + datetime.timedelta(minutes=5)

events = []
pat = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\.\d+.*?\[com\.kainor\.lapslock:perf\]\s+(.*)$")
for line in open(log_path):
    m = pat.match(line.strip())
    if not m:
        continue
    events.append((datetime.datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S"), m.group(2)))

def phase_of(t):
    current = None
    for w, n in starts:
        if t >= w:
            current = n
    if t > end_time:
        return None
    return current

stats = collections.OrderedDict((n, {"bodies": collections.Counter(), "filters": [], "marks": []}) for _, n in starts)
for t, msg in events:
    p = phase_of(t)
    if p is None:
        continue
    if msg.startswith("body "):
        stats[p]["bodies"][msg[5:].strip()] += 1
    elif msg.startswith("deviceFilter"):
        ms = float(re.search(r"ms=([\d.]+)", msg).group(1))
        stats[p]["filters"].append(ms)
    else:
        stats[p]["marks"].append(msg)

views = ["AppRootView", "ModuleShell", "DeviceListView", "DeviceDetailView", "SecurityListView", "PersonGroupsView"]
print("| Phase | " + " | ".join(views) + " | Device filter runs | Filter ms total | Filter ms max |")
print("|" + "---|" * (len(views) + 4))
for p, s in stats.items():
    f = s["filters"]
    row = [p] + [str(s["bodies"].get(v, 0)) for v in views] + [str(len(f)), "%.0f" % sum(f), "%.1f" % (max(f) if f else 0)]
    print("| " + " | ".join(row) + " |")
print()
for p, s in stats.items():
    for m in s["marks"]:
        print(p + ": " + m)
