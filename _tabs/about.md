---
# the default layout is 'page'
icon: fas fa-info-circle
order: 4
---

## Hi, I'm Zohir (aka 𝙽!𝙻)

Welcome to my personal archive.

I’m a security researcher and CTF player with **150+ events** behind me. This site is where I keep the parts of the journey that matter: the experiments that worked, the debugging sessions that didn’t, the weird corner cases, the lessons that only show up after you stare at a crash dump for too long, and the notes that I wish existed when I started.

If you’re into **reverse engineering**, **OS internals**, **memory forensics**, or **malware analysis/development**, you’re in the right place.

---

## What this blog is

This blog is not a “portfolio” page and it’s not meant to be polished marketing.

It’s a **technical notebook**:

- Writeups from CTF challenges (and the techniques behind them)
- Reversing notes (static + dynamic analysis)
- Low-level systems topics (Windows/Linux internals, process/memory details, debugging)
- Forensics notes (memory artifacts, triage patterns, what to look for first)
- Malware-focused research (understanding behavior, persistence, evasion ideas, tradecraft lessons)

Sometimes I’ll publish full solutions. Sometimes I’ll publish partial notes that are still useful. Either way, the goal is to stay honest and build a trail I can reference later.

---

## The themes I care about

### Reverse engineering

I like breaking software apart and rebuilding understanding from the bottom up:

- Recognizing compiler patterns
- Identifying control flow tricks
- Extracting protocols and file formats
- Recovering data structures and intent from “just bytes”



### OS internals

I’m interested in how the system really behaves—not the clean diagram version, but the version you meet at 3AM when something crashes, something deadlocks, or something “works on my machine” and nowhere else. I like following the trail from a symptom to a cause: watching processes and threads change state, tracking handles and loaded modules, and digging through memory until the story makes sense. Most of the time it’s not glamorous; it’s just you, a debugger, and a lot of tiny details. But that moment when the crash finally *explains itself* is exactly why I keep coming back.



### Memory forensics (4n6)

Memory is where you can catch the truth:

- What’s running vs what claims to be running
- What was injected, hollowed, mapped, or staged
- What artifacts remain even when files disappear

I like building repeatable mental checklists and workflows.

### Malware analysis and development

Understanding malware means understanding both sides:

- How payloads execute, persist, and communicate
- How analysis is evaded and how analysts counter that
- What tradecraft looks like when it meets reality

I treat this as **research and learning**—the focus here is analysis and defensive understanding, plus controlled lab experiments.

---

## What I’m trying to achieve

This page is long because my goal is long-term.

Here’s what I want this site to become over time:

1. **A reliable personal knowledge base**
	- I want to be able to search my own notes and instantly remember the technique, the command, the pitfall, and the fix.

2. **A trail of improvement**
	- Better writeups, deeper analysis, cleaner methodology.

3. **A bridge between CTF skills and real binaries**
	- CTFs train speed and creativity.
	- Real-world reversing trains patience, verification, and humility.
	- I want to connect both worlds.

4. **A place where I can publish experiments**
	- Small tools
	- Notes from debugging sessions
	- Mini research topics that don’t fit into “one post, one result”

---

## My approach

When I write technical posts here, I try to follow a simple approach:

- **Reproduce first** (make the behavior reliable)
- **Observe second** (instrumentation, logs, tracing, debugger)
- **Explain third** (what is happening and why)
- **Generalize last** (how to recognize and reuse the technique)

If I can’t explain something clearly, I treat it as “not understood yet” and I’ll keep digging.

---

## What you’ll find here (content types)

Expect posts like:

- CTF writeups (pwn/rev/misc/forensics—whatever I’m actively grinding)
- Reverse engineering walkthroughs (functions → flow → structures → behavior)
- OS internals notes (concepts explained through experiments)
- Malware behavior breakdowns (in a lab environment)
- Memory forensics notes (artifacts, triage hints, tooling habits)

---

## Contact / links

You can find me here:

- GitHub: https://github.com/ZX41R
- LinkedIn: https://www.linkedin.com/in/hakmi-zohir-87b896299
- Medium: https://medium.com/@Zx41R
