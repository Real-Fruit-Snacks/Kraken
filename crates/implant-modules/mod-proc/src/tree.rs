//! Process tree building from a flat process list

use common::{ProcessInfo, ProcessTree, ProcessTreeNode};
use std::collections::HashMap;

/// Build a process tree from a flat list of ProcessInfo entries.
/// If root_pid is Some(pid) and non-zero, return only the subtree rooted at that pid.
/// If root_pid is None or 0, return the full forest.
pub fn build_tree(processes: &[ProcessInfo], root_pid: Option<u32>) -> ProcessTree {
    // Map pid -> index in processes slice
    let pid_set: std::collections::HashSet<u32> = processes.iter().map(|p| p.pid).collect();

    // Group children by ppid
    let mut children_map: HashMap<u32, Vec<&ProcessInfo>> = HashMap::new();
    for proc in processes {
        children_map.entry(proc.ppid).or_default().push(proc);
    }

    let filter_pid = root_pid.unwrap_or(0);

    if filter_pid != 0 {
        // Return subtree rooted at filter_pid
        if let Some(root_proc) = processes.iter().find(|p| p.pid == filter_pid) {
            let node = build_node(root_proc, &children_map);
            ProcessTree { nodes: vec![node] }
        } else {
            ProcessTree { nodes: vec![] }
        }
    } else {
        // Find root processes: those whose ppid is not in the process list,
        // or whose ppid == pid (init/kernel threads), or ppid == 0
        let mut roots: Vec<&ProcessInfo> = processes
            .iter()
            .filter(|p| p.ppid == 0 || p.ppid == p.pid || !pid_set.contains(&p.ppid))
            .collect();

        roots.sort_by_key(|p| p.pid);

        let nodes = roots
            .iter()
            .map(|p| build_node(p, &children_map))
            .collect();

        ProcessTree { nodes }
    }
}

fn build_node(proc: &ProcessInfo, children_map: &HashMap<u32, Vec<&ProcessInfo>>) -> ProcessTreeNode {
    let mut children: Vec<&ProcessInfo> = children_map
        .get(&proc.pid)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        // Avoid infinite loops for self-parenting processes
        .filter(|p| p.pid != proc.pid)
        .collect();

    children.sort_by_key(|p| p.pid);

    let child_nodes = children
        .iter()
        .map(|c| build_node(c, children_map))
        .collect();

    ProcessTreeNode {
        pid: proc.pid,
        ppid: proc.ppid,
        name: proc.name.clone(),
        children: child_nodes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_proc(pid: u32, ppid: u32, name: &str) -> ProcessInfo {
        ProcessInfo {
            pid,
            ppid,
            name: name.to_string(),
            path: None,
            user: None,
            arch: None,
        }
    }

    #[test]
    fn test_simple_tree() {
        let procs = vec![
            make_proc(1, 0, "init"),
            make_proc(2, 1, "bash"),
            make_proc(3, 2, "ls"),
        ];

        let tree = build_tree(&procs, None);
        assert_eq!(tree.nodes.len(), 1);
        assert_eq!(tree.nodes[0].pid, 1);
        assert_eq!(tree.nodes[0].children.len(), 1);
        assert_eq!(tree.nodes[0].children[0].pid, 2);
        assert_eq!(tree.nodes[0].children[0].children[0].pid, 3);
    }

    #[test]
    fn test_subtree() {
        let procs = vec![
            make_proc(1, 0, "init"),
            make_proc(2, 1, "bash"),
            make_proc(3, 2, "ls"),
            make_proc(4, 1, "sshd"),
        ];

        let tree = build_tree(&procs, Some(2));
        assert_eq!(tree.nodes.len(), 1);
        assert_eq!(tree.nodes[0].pid, 2);
        assert_eq!(tree.nodes[0].children.len(), 1);
        assert_eq!(tree.nodes[0].children[0].pid, 3);
    }

    #[test]
    fn test_missing_root_pid() {
        let procs = vec![make_proc(1, 0, "init")];
        let tree = build_tree(&procs, Some(999));
        assert!(tree.nodes.is_empty());
    }
}
