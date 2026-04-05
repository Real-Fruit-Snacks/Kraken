# Kraken Operator Command Reference

The Kraken Operator is a terminal user interface (TUI) for controlling implants across your C2 infrastructure. Built with [ratatui](https://github.com/ratatui-org/ratatui) and styled with the Catppuccin Mocha color theme, it provides a responsive, keyboard-driven interface for managing implants and executing commands.

## Table of Contents

- [Getting Started](#getting-started)
- [Interface Overview](#interface-overview)
- [Global Keybindings](#global-keybindings)
- [Views](#views)
- [Commands](#commands)
- [Status Indicators](#status-indicators)
- [Examples](#examples)
- [Troubleshooting](#troubleshooting)

---

## Getting Started

### Starting the Operator

```bash
kraken-operator [OPTIONS]
```

### Connection Options

The operator accepts the following command-line arguments:

| Option | Default | Description |
|--------|---------|-------------|
| `-s, --server <ADDRESS>` | `http://127.0.0.1:50051` | Teamserver address and port |
| `--log-level <LEVEL>` | `info` | Logging verbosity (trace, debug, info, warn, error) |

### Example

Connect to a remote teamserver:

```bash
kraken-operator --server http://192.168.1.100:50051 --log-level debug
```

The operator will attempt to connect and display the connection status in the status bar at the bottom of the screen.

---

## Interface Overview

The Kraken Operator consists of four main views:

1. **Sessions** - View and manage all implants
2. **Interact** - Execute commands on a selected implant
3. **Events** - Monitor real-time events from the teamserver
4. **Help** - Display keybinding reference

At the bottom of every view is a **status bar** showing:
- Current connection status
- Available view navigation and help options
- Quick reference for common actions

```
 Connected to http://127.0.0.1:50051 | Tab: switch view | ?: help | Ctrl+C: quit
```

---

## Global Keybindings

These keybindings work in all views (except when typing commands):

| Key | Action |
|-----|--------|
| `Tab` | Switch to next view (Sessions → Interact → Events → Help) |
| `?` | Toggle help overlay |
| `j` or `↓` | Move selection down (in lists) |
| `k` or `↑` | Move selection up (in lists) |
| `Ctrl+C` or `Ctrl+Q` | Quit the operator |

### Help Overlay

Press `?` to display a searchable help menu showing all available keybindings and commands. Press `?` or `Esc` to close the overlay.

---

## Views

### Sessions View

**The Sessions view is your control center.** It displays all registered implants with their current status, metadata, and last check-in time.

#### Layout

```
Sessions
┌────────────────────────────────────────────────────────────┐
│ ID     Name      State    Hostname      User         OS    │
├────────────────────────────────────────────────────────────┤
│ a1b2c3 implant1  active   web-server    www-data    Linux │
│ d4e5f6 implant2  lost     desktop-pc    admin       Win11 │
│ g7h8i9 implant3  staging  backup-srv    root        Linux │
│ j0k1l2 implant4  burned   dev-machine   developer   macOS │
└────────────────────────────────────────────────────────────┘
```

#### Keybindings

| Key | Action |
|-----|--------|
| `j` or `↓` | Move selection down |
| `k` or `↑` | Move selection up |
| `Enter` | Select implant and enter Interact view |
| `r` | Refresh implant list from teamserver |
| `Tab` | Switch to Events view |

#### Status Colors

Each implant's state is displayed with a distinct color:

- **Active** (green) - Implant is checking in normally, ready for commands
- **Staging** (blue) - Implant registered but not yet checking in
- **Lost** (yellow) - Implant missed check-in windows, connection may be unstable
- **Burned** (red) - Implant marked as compromised, avoid further use
- **Retired** (dim) - Implant decommissioned or retired from service

---

### Interact View

**The Interact view is where you control a single implant.** It displays command history and results, and provides an input line for typing new commands.

#### Layout

```
Interact - implant1 (a1b2c3)
┌──────────────────────────────────────────────────────────────┐
│ [10:23:45] info Interacting with implant1                   │
│ [10:23:46] command shell whoami                             │
│ [10:23:47] info Task dispatched (waiting for result...)     │
│                                                              │
│                                                              │
└──────────────────────────────────────────────────────────────┘
┌──────────────────────────────────────────────────────────────┐
│ >shell                                                       │
└──────────────────────────────────────────────────────────────┘
```

Output lines are color-coded by type:

- **command** (white) - Commands you've issued
- **stdout** (green) - Command output from the implant
- **stderr** (red) - Command errors
- **info** (blue) - System messages and task status
- **error** (red) - Operator errors

#### Keybindings

| Key | Action |
|-----|--------|
| Type characters | Build your command |
| `Enter` | Execute the command |
| `↑` or `↓` | Scroll output (up/down through history) |
| `←` or `→` | Move cursor within input line |
| `Backspace` | Delete character before cursor |
| `Esc` | Return to Sessions view and cancel input |
| `Tab` | Switch to Events view |

#### Input Editing

The input line supports basic editing:

- **Arrow keys** - Move cursor left/right
- **Backspace** - Delete character before cursor
- **Character keys** - Insert at cursor position

Text input is line-based; scroll the output with `↑`/`↓` while not editing.

---

### Events View

**The Events view provides real-time visibility into teamserver activity.** Track implant checkins, task completions, and system events.

#### Layout

```
Events
┌──────────────────────────────────────────────────────────────┐
│ [10:24:01] IMPLANT_CHECKIN: implant2 (d4e5f6)              │
│ [10:24:02] TASK_COMPLETE: shell (implant1)                 │
│ [10:24:05] IMPLANT_LOST: implant3 (g7h8i9)                 │
│ [10:24:10] IMPLANT_REGISTRATION: implant5 (m3n4o5)         │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

#### Keybindings

| Key | Action |
|-----|--------|
| `j` or `↓` | Move selection down |
| `k` or `↑` | Move selection up |
| `Tab` | Switch to Sessions view |
| `Esc` | Return to Sessions view |

#### Event Types

- **IMPLANT_REGISTRATION** - New implant registered with teamserver
- **IMPLANT_CHECKIN** - Implant checked in at scheduled interval
- **IMPLANT_LOST** - Implant missed check-in deadline
- **TASK_DISPATCH** - Command sent to implant
- **TASK_COMPLETE** - Implant returned task results
- **IMPLANT_BURNED** - Implant marked as compromised

---

### Help View

**The Help view displays all keybindings and commands at a glance.**

Press `?` at any time to open the help overlay. This displays a summary of:

- Navigation keybindings (Tab, j/k, Enter, Esc)
- Command syntax
- Global shortcuts (Ctrl+C, ?)

Press `?` or `Esc` to close the overlay and return to the previous view.

---

## Commands

Commands are executed in the **Interact view** after selecting an implant.

### Shell Execution

Execute arbitrary shell commands on the implant.

```
shell <command>
```

or shorter:

```
sh <command>
```

**Examples:**

```
shell whoami
shell cat /etc/passwd
shell ps aux
shell ls -la /tmp
sh id
sh netstat -tuln
```

**Output:** The implant executes the command and returns stdout/stderr. Results appear in the output area with timestamp and type labels.

---

### Sleep (Check-in Interval)

Change the implant's check-in interval. This controls how often the implant contacts the teamserver.

```
sleep <seconds>
```

**Examples:**

```
sleep 30       # Check in every 30 seconds
sleep 300      # Check in every 5 minutes
sleep 3600     # Check in every hour
```

**Behavior:**
- Takes effect on the implant's next check-in cycle
- Useful for reducing detection risk (longer intervals = fewer network signatures)
- Use shorter intervals when troubleshooting connection issues

---

### Burn

Mark an implant as burned (compromised) and prevent further commands.

```
burn
```

**Use when:**
- You suspect the implant has been discovered
- The implant's operating system has been updated
- You're permanently retiring an implant

**Effect:** The implant's state changes to "burned" in the Sessions view, and new commands are rejected.

---

### Navigation

Return to the Sessions view.

```
back
```

or shorter:

```
b
```

---

### Exit/Quit

Exit the current implant interaction (alias for `back`).

```
exit
quit
q
```

---

### Refresh

Refresh implant list and metadata from the teamserver.

```
refresh
```

or shorter:

```
r
```

**Useful when:**
- You suspect stale data in the Sessions view
- You've just registered a new implant
- Status indicators appear incorrect

---

### Help

Display the help overlay.

```
help
?
```

Same as pressing `?` globally.

---

## Status Indicators

Implant status is displayed as text in the Sessions view and with color coding throughout the interface.

| Status | Color | Meaning | Action |
|--------|-------|---------|--------|
| **active** | Green | Implant is healthy and checking in on schedule | Safe to execute commands |
| **staging** | Blue | Implant registered but hasn't checked in yet | Wait for first check-in or verify connectivity |
| **lost** | Yellow | Implant missed one or more check-in windows | Connection may be unstable; consider shorter commands or increased intervals |
| **burned** | Red | Implant marked as compromised (manual or automatic) | Do not use; remove or retire cleanly |
| **retired** | Dim | Implant is decommissioned | No longer available; remove from service |

### Last Seen Timestamp

Each implant in the Sessions view displays a "Last Seen" timestamp (HH:MM:SS format):

- **Recent** (within check-in interval) - Implant is healthy
- **Stale** (beyond check-in interval) - Implant may be lost; check status
- **Never** - Implant never checked in; verify deployment

---

## Examples

### Scenario 1: Basic Reconnaissance

Select an implant and gather system information:

```
shell whoami
shell id
shell uname -a
shell pwd
```

**Expected output:**
```
[10:25:01] command shell whoami
[10:25:02] info Task dispatched (waiting for result...)
[10:25:03] stdout www-data
```

---

### Scenario 2: Persistence Check

Verify implant startup configuration:

```
shell crontab -l
shell ls /etc/init.d/
shell systemctl list-unit-files | grep enabled
```

---

### Scenario 3: Network Enumeration

Map network topology:

```
shell ip addr show
shell route -n
shell netstat -tulpn
shell nmap -sn 192.168.1.0/24
```

---

### Scenario 4: Reducing Detection Risk

Lower check-in frequency and refresh status:

```
sleep 600
refresh
```

The implant now checks in every 10 minutes instead of the default. This reduces network signatures.

---

### Scenario 5: Burning an Implant

When you suspect compromise:

```
burn
```

Return to Sessions view and verify the implant state changed to "burned" (red).

---

## Troubleshooting

### Connection Failed

**Problem:** Operator shows "Connection failed: ..." in status bar.

**Solutions:**
1. Verify teamserver is running: `curl http://<server>:50051`
2. Check firewall rules allow access to port 50051
3. Verify correct server address: `-s http://<correct-ip>:50051`
4. Check logs in `logs/operator.log` for detailed error messages

### No Implants Appearing

**Problem:** Sessions view is empty after connecting.

**Solutions:**
1. Verify implants have registered: Check Events view for IMPLANT_REGISTRATION events
2. Refresh manually: Press `r` in Sessions view
3. Check teamserver implant count via logs or API
4. Verify implant configuration and network connectivity

### Commands Not Executing

**Problem:** Commands appear in output but don't execute.

**Solutions:**
1. Verify implant state is "active" (green) in Sessions view
2. Use full command path: `/usr/bin/whoami` instead of `whoami`
3. Check implant check-in frequency: May be too long (adjust with `sleep`)
4. Verify implant has permissions on target system
5. Check Events view for TASK_COMPLETE events confirming command receipt

### Output Stuck or Delayed

**Problem:** Command output appears frozen or is delayed.

**Solutions:**
1. Implant may be executing a long-running command; wait or interrupt on implant
2. Check implant check-in interval: `sleep 10` to increase frequency
3. Scroll up/down in output with `↑`/`↓` to refresh view
4. Press `r` (refresh) to resync with teamserver
5. Verify network connectivity between implant and teamserver

### Can't Return to Sessions View

**Problem:** Stuck in Interact view.

**Solutions:**
1. Press `Esc` to return to Sessions view
2. Type `back` or `b` and press `Enter`
3. Press `Tab` to cycle to other views
4. Use `Ctrl+C` to quit and restart operator if necessary

### Text Input Not Working

**Problem:** Typed commands don't appear in input line.

**Solutions:**
1. Verify you're in Interact view and not Help overlay
2. Close help overlay if open: Press `?` or `Esc`
3. Ensure input line is active (appears at bottom of Interact view)
4. Check terminal encoding: Operator expects UTF-8
5. Try simpler commands with ASCII characters only

### Logs Not Writing

**Problem:** `logs/operator.log` is not created or updated.

**Solutions:**
1. Verify write permissions in current directory
2. Create `logs/` directory manually: `mkdir logs`
3. Restart operator: `kraken-operator`
4. Check system logs for file permission errors
5. Increase log level: `--log-level debug` for more detail

---

## Performance Tips

### Large Implant Counts

If managing 100+ implants:

1. Use status filters (coming in future versions)
2. Refresh less frequently: Press `r` only when needed
3. Avoid very short check-in intervals (> 10 seconds)
4. Monitor teamserver resource usage

### Network Efficiency

1. Use longer check-in intervals when not actively commanding: `sleep 300` (5 min)
2. Batch commands on staging implants before activation
3. Monitor Events view for lost implants and investigate before sending more tasks
4. Use shorter intervals (`sleep 10`) only during active operations

### Terminal Performance

1. Resize terminal to reduce rendering load (minimum 80x24)
2. Close other terminal multiplexer windows
3. Disable logging or increase log level: `--log-level error`
4. Restart operator if responsiveness degrades

---

## File Locations

- **Logs:** `logs/operator.log` - Operator activity and errors
- **Configuration:** Passed via command-line arguments only (no config file)
- **State:** No persistent state between sessions (reset on restart)

---

## Color Scheme (Catppuccin Mocha)

The operator uses the Catppuccin Mocha color theme for accessibility and aesthetics:

- **Backgrounds:** Dark navy (`#1e1e2e`)
- **Text:** Light gray (`#cdd6f4`)
- **Accents:** Lavender, Mauve, Blue, Green, Red, Yellow
- **Highlights:** Bold mauve for selection

All colors are automatically adjusted for terminal capability (256-color, true color, etc.).

---

## Advanced Topics

### Scripting Multiple Implants

While the operator is interactive, you can:

1. Write a script to execute commands sequentially
2. Use the teamserver API directly for batch operations
3. Export implant IDs from Sessions view and process programmatically

### Integration with External Tools

The operator logs all activity to `logs/operator.log`. You can:

1. Tail the log: `tail -f logs/operator.log`
2. Parse events from the log for alerts or metrics
3. Integrate with SIEM or monitoring tools

### Custom Commands (Future)

The architecture supports adding new commands. Current commands are hardcoded; future versions may support plugins or scripting.

---

## Keyboard Layout Reference

This guide assumes a standard QWERTY keyboard. If using alternative layouts:

- `j/k` may differ; use arrow keys instead
- Commands are English-based and layout-independent
- Navigation works the same regardless of layout

---

## Support and Feedback

For issues, feature requests, or feedback:

1. Check this documentation and Troubleshooting section
2. Review `logs/operator.log` for error details
3. Consult the Kraken project documentation
4. Open an issue with logs and reproduction steps

---

## Version

This documentation applies to **Kraken Operator** with:

- UI Framework: ratatui
- Theme: Catppuccin Mocha
- Protocol: gRPC to Kraken Teamserver

Check operator version with: `kraken-operator --version`
