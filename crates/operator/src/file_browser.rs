/// File browser state management for per-session directory tracking

/// Per-session file browser state with directory stack
#[derive(Debug, Clone, Default)]
pub struct FileBrowserState {
    /// Client-tracked current working directory
    pub cwd: String,
    /// Directory stack for pushd/popd operations
    pub dir_stack: Vec<String>,
}

impl FileBrowserState {
    /// Create a new file browser state with unknown cwd
    pub fn new() -> Self {
        Self {
            cwd: String::new(),
            dir_stack: Vec::new(),
        }
    }

    /// Push current directory onto stack and change to new path
    /// Returns the previous working directory
    pub fn pushd(&mut self, path: &str) -> String {
        let old_cwd = self.cwd.clone();
        self.dir_stack.push(old_cwd.clone());
        self.cwd = path.to_string();
        old_cwd
    }

    /// Pop directory from stack and return to it
    /// Returns Some(path) if stack not empty, None otherwise
    pub fn popd(&mut self) -> Option<String> {
        self.dir_stack.pop().map(|dir| {
            self.cwd = dir.clone();
            dir
        })
    }

    /// Return reference to directory stack contents
    pub fn dirs(&self) -> &[String] {
        &self.dir_stack
    }

    /// Update the current working directory
    pub fn update_cwd(&mut self, path: &str) {
        self.cwd = path.to_string();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_state() {
        let state = FileBrowserState::new();
        assert_eq!(state.cwd, "");
        assert!(state.dir_stack.is_empty());
    }

    #[test]
    fn test_update_cwd() {
        let mut state = FileBrowserState::new();
        state.update_cwd("/home/user");
        assert_eq!(state.cwd, "/home/user");
    }

    #[test]
    fn test_pushd() {
        let mut state = FileBrowserState::new();
        state.update_cwd("/home/user");

        let old = state.pushd("/tmp");
        assert_eq!(old, "/home/user");
        assert_eq!(state.cwd, "/tmp");
        assert_eq!(state.dir_stack, vec!["/home/user"]);
    }

    #[test]
    fn test_popd() {
        let mut state = FileBrowserState::new();
        state.update_cwd("/home/user");
        state.pushd("/tmp");
        state.pushd("/var");

        let dir = state.popd();
        assert_eq!(dir, Some("/tmp".to_string()));
        assert_eq!(state.cwd, "/tmp");

        let dir = state.popd();
        assert_eq!(dir, Some("/home/user".to_string()));
        assert_eq!(state.cwd, "/home/user");

        let dir = state.popd();
        assert_eq!(dir, None);
    }

    #[test]
    fn test_dirs() {
        let mut state = FileBrowserState::new();
        state.update_cwd("/home/user");
        state.pushd("/tmp");
        state.pushd("/var");

        let dirs = state.dirs();
        assert_eq!(dirs, &["/home/user", "/tmp"]);
    }
}
