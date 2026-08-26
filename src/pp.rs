// Verbosity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verbosity {
    Quiet,
    Notice,
    Info,
    Verbose,
}

const INDENT_PREFIX: &str = "   ";

pub struct PP {
    pub verbosity: Verbosity,
    indent: usize,
}

impl PP {
    pub fn new(quiet: bool) -> Self {
        Self {
            verbosity: if quiet {
                Verbosity::Quiet
            } else {
                Verbosity::Verbose
            },
            indent: 0,
        }
    }

    #[cfg(test)]
    pub fn default_pp() -> Self {
        Self::new(false)
    }

    pub fn is_showing(&self, level: Verbosity) -> bool {
        self.verbosity >= level
    }

    pub fn indent(&self) -> PP {
        PP {
            verbosity: self.verbosity,
            indent: self.indent + 1,
        }
    }

    fn output(&self, msg: &str) {
        println!("{}{msg}", INDENT_PREFIX.repeat(self.indent));
    }

    fn output_err(&self, msg: &str) {
        eprintln!("{}{msg}", INDENT_PREFIX.repeat(self.indent));
    }

    pub fn infof(&self, msg: &str) {
        if self.is_showing(Verbosity::Info) {
            self.output(msg);
        }
    }

    pub fn noticef(&self, msg: &str) {
        if self.is_showing(Verbosity::Notice) {
            self.output(msg);
        }
    }

    pub fn warningf(&self, msg: &str) {
        self.output_err(msg);
    }

    pub fn errorf(&self, msg: &str) {
        self.output_err(msg);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `quiet` suppresses info and notice output; the default shows everything.
    /// Warnings and errors bypass the gate entirely and go to stderr.
    #[test]
    fn quiet_gates_output_levels() {
        let quiet = PP::new(true);
        assert!(quiet.is_showing(Verbosity::Quiet));
        assert!(!quiet.is_showing(Verbosity::Notice));
        assert!(!quiet.is_showing(Verbosity::Info));

        let verbose = PP::new(false);
        assert!(verbose.is_showing(Verbosity::Quiet));
        assert!(verbose.is_showing(Verbosity::Notice));
        assert!(verbose.is_showing(Verbosity::Info));
        assert!(verbose.is_showing(Verbosity::Verbose));
    }

    /// Intermediate levels aren't reachable from `new`, but `is_showing` must
    /// still order them correctly.
    #[test]
    fn intermediate_levels_are_ordered() {
        let mut pp = PP::new(false);
        pp.verbosity = Verbosity::Notice;
        assert!(pp.is_showing(Verbosity::Notice));
        assert!(!pp.is_showing(Verbosity::Info));

        pp.verbosity = Verbosity::Info;
        assert!(pp.is_showing(Verbosity::Info));
        assert!(!pp.is_showing(Verbosity::Verbose));
    }

    /// Nested indent levels accumulate and carry verbosity down, which is what
    /// the config summary relies on.
    #[test]
    fn indent_nests_and_preserves_verbosity() {
        let pp = PP::new(true);
        assert_eq!(pp.indent, 0);
        let child = pp.indent();
        assert_eq!(child.indent, 1);
        assert_eq!(child.indent().indent, 2);
        assert_eq!(child.verbosity, pp.verbosity);
    }
}
