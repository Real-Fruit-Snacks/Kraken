//! Process tree building and rendering utilities

use std::collections::{HashMap, HashSet};
use console::style;
use protocol::ProcessEntry;
use crate::theme::colors;

/// Tree node representing a process and its children
#[derive(Debug, Clone)]
pub struct TreeNode {
    pub process: ProcessEntry,
    pub children: Vec<TreeNode>,
    pub depth: usize,
}

/// Build a process tree from a flat list of ProcessEntry structs
///
/// This function:
/// - Parses PPID relationships to construct hierarchy
/// - Detects cycles to prevent infinite recursion
/// - Handles orphaned processes (PPID not in process list)
/// - Returns root nodes (processes with no parent or orphaned)
pub fn build_tree(processes: &[ProcessEntry]) -> Vec<TreeNode> {
    if processes.is_empty() {
        return Vec::new();
    }

    // Index processes by PID for quick lookup
    let mut pid_map: HashMap<u32, &ProcessEntry> = HashMap::new();
    for proc in processes {
        pid_map.insert(proc.pid, proc);
    }

    // Group processes by PPID
    let mut children_map: HashMap<u32, Vec<&ProcessEntry>> = HashMap::new();
    for proc in processes {
        children_map.entry(proc.ppid).or_default().push(proc);
    }

    // Find root processes (PPID = 0 or PPID not in process list)
    let mut roots = Vec::new();
    let mut visited = HashSet::new();

    for proc in processes {
        // Root if PPID is 0 or parent doesn't exist in our process list
        if proc.ppid == 0 || !pid_map.contains_key(&proc.ppid) {
            if visited.insert(proc.pid) {
                roots.push(build_subtree(proc, &children_map, &mut visited, 0));
            }
        }
    }

    // Handle case where all processes have parents but there's a cycle
    // Add any unvisited processes as roots
    for proc in processes {
        if !visited.contains(&proc.pid) {
            visited.insert(proc.pid);
            roots.push(build_subtree(proc, &children_map, &mut visited, 0));
        }
    }

    roots
}

/// Recursively build a subtree from a process
fn build_subtree(
    process: &ProcessEntry,
    children_map: &HashMap<u32, Vec<&ProcessEntry>>,
    visited: &mut HashSet<u32>,
    depth: usize,
) -> TreeNode {
    let mut children = Vec::new();

    if let Some(child_procs) = children_map.get(&process.pid) {
        for child in child_procs {
            // Cycle detection: skip if already visited
            if visited.insert(child.pid) {
                children.push(build_subtree(child, children_map, visited, depth + 1));
            }
        }
    }

    TreeNode {
        process: process.clone(),
        children,
        depth,
    }
}

/// Render the process tree with Unicode box-drawing characters
///
/// Output format:
/// ```text
/// PID    | Name              | User         | Arch  | Flags
/// ────────────────────────────────────────────────────────────
/// 1      | systemd           | root         | x64   |
/// ├─ 100 | sshd              | root         | x64   |
/// │  └─ 200 | bash           | user         | x64   | [CURRENT]
/// └─ 300 | nginx             | www-data     | x64   | [INJECTABLE]
/// ```
pub fn render_tree(nodes: &[TreeNode]) -> String {
    if nodes.is_empty() {
        return String::from("No processes to display\n");
    }

    let mut output = String::new();

    // Header
    output.push_str(&format!(
        "{:<7} | {:<20} | {:<15} | {:<6} | {}\n",
        "PID", "Name", "User", "Arch", "Flags"
    ));
    output.push_str(&"─".repeat(80));
    output.push('\n');

    // Render each root and its children
    for (idx, node) in nodes.iter().enumerate() {
        let is_last_root = idx == nodes.len() - 1;
        render_node(node, "", is_last_root, &mut output);
    }

    output
}

/// Recursively render a tree node with proper indentation and connectors
fn render_node(node: &TreeNode, prefix: &str, is_last: bool, output: &mut String) {
    // Determine flags to display
    let mut flags = Vec::new();
    if node.process.is_current {
        flags.push(style("[CURRENT]").fg(colors::GREEN).to_string());
    }
    if node.process.is_injectable {
        flags.push(style("[INJECTABLE]").fg(colors::YELLOW).to_string());
    }
    if node.process.is_elevated {
        flags.push(style("[ELEVATED]").fg(colors::RED).to_string());
    }
    let flags_str = flags.join(" ");

    // Truncate long names/users for alignment
    let name = if node.process.name.len() > 20 {
        format!("{}...", &node.process.name[..17])
    } else {
        node.process.name.clone()
    };

    let user = if node.process.user.len() > 15 {
        format!("{}...", &node.process.user[..12])
    } else {
        node.process.user.clone()
    };

    // Format the current line
    if node.depth == 0 {
        // Root node - no prefix
        output.push_str(&format!(
            "{:<7} | {:<20} | {:<15} | {:<6} | {}\n",
            node.process.pid, name, user, node.process.arch, flags_str
        ));
    } else {
        // Child node - with tree connectors
        let connector = if is_last { "└─ " } else { "├─ " };
        output.push_str(&format!(
            "{}{}{:<7} | {:<20} | {:<15} | {:<6} | {}\n",
            prefix, connector, node.process.pid, name, user, node.process.arch, flags_str
        ));
    }

    // Render children with updated prefix
    let child_count = node.children.len();
    for (idx, child) in node.children.iter().enumerate() {
        let is_last_child = idx == child_count - 1;

        // Build prefix for children
        let child_prefix = if node.depth == 0 {
            String::new()
        } else {
            let continuation = if is_last { "   " } else { "│  " };
            format!("{}{}", prefix, continuation)
        };

        render_node(child, &child_prefix, is_last_child, output);
    }
}

/// Filter tree nodes by process name (case-insensitive substring match)
///
/// Preserves parent-child relationships:
/// - If a node matches, include it and all its children
/// - If a child matches, include its path from the root
pub fn filter_tree(nodes: &[TreeNode], name_pattern: &str) -> Vec<TreeNode> {
    if name_pattern.is_empty() {
        return nodes.to_vec();
    }

    let pattern_lower = name_pattern.to_lowercase();
    nodes
        .iter()
        .filter_map(|node| filter_node(node, &pattern_lower))
        .collect()
}

/// Recursively filter a single node and its children
fn filter_node(node: &TreeNode, pattern: &str) -> Option<TreeNode> {
    let name_matches = node.process.name.to_lowercase().contains(pattern);

    // Recursively filter children
    let filtered_children: Vec<TreeNode> = node
        .children
        .iter()
        .filter_map(|child| filter_node(child, pattern))
        .collect();

    // Include this node if:
    // 1. Its name matches the pattern, OR
    // 2. Any of its descendants match (filtered_children is non-empty)
    if name_matches || !filtered_children.is_empty() {
        Some(TreeNode {
            process: node.process.clone(),
            children: filtered_children,
            depth: node.depth,
        })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_process(pid: u32, ppid: u32, name: &str) -> ProcessEntry {
        ProcessEntry {
            pid,
            ppid,
            name: name.to_string(),
            path: String::new(),
            user: "test".to_string(),
            arch: "x64".to_string(),
            integrity: 0,
            is_elevated: false,
            is_current: false,
            is_injectable: false,
            warning: String::new(),
        }
    }

    #[test]
    fn test_build_simple_tree() {
        let processes = vec![
            make_process(1, 0, "init"),
            make_process(2, 1, "child1"),
            make_process(3, 1, "child2"),
        ];

        let tree = build_tree(&processes);
        assert_eq!(tree.len(), 1);
        assert_eq!(tree[0].process.pid, 1);
        assert_eq!(tree[0].children.len(), 2);
    }

    #[test]
    fn test_cycle_detection() {
        // Process 2 is parent of 3, and 3 is parent of 2 (cycle)
        let processes = vec![
            make_process(1, 0, "init"),
            make_process(2, 3, "proc2"),
            make_process(3, 2, "proc3"),
        ];

        let tree = build_tree(&processes);
        // Should not panic, cycle should be detected
        assert!(!tree.is_empty());
    }

    #[test]
    fn test_orphaned_processes() {
        // Process 2 has PPID 99 which doesn't exist
        let processes = vec![
            make_process(1, 0, "init"),
            make_process(2, 99, "orphan"),
        ];

        let tree = build_tree(&processes);
        assert_eq!(tree.len(), 2); // Both should be roots
    }

    #[test]
    fn test_filter_tree() {
        let processes = vec![
            make_process(1, 0, "systemd"),
            make_process(2, 1, "sshd"),
            make_process(3, 1, "nginx"),
        ];

        let tree = build_tree(&processes);
        let filtered = filter_tree(&tree, "ssh");

        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].children.len(), 1);
        assert_eq!(filtered[0].children[0].process.name, "sshd");
    }

    #[test]
    fn test_empty_tree() {
        let tree = build_tree(&[]);
        assert!(tree.is_empty());

        let output = render_tree(&[]);
        assert!(output.contains("No processes"));
    }
}
